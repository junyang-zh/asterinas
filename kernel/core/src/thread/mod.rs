// SPDX-License-Identifier: MPL-2.0

//! Thread implementation.

use core::sync::atomic::{AtomicBool, Ordering};

use aster_util::per_cpu_counter::PerCpuCounter;
use ostd::{
    cpu::{CpuId, CpuSet, PinCurrentCpu},
    irq::DisabledLocalIrqGuard,
    sync::{LocalIrqDisabled, RcuOption, Waiter, Waker},
    task::Task,
};

use self::{kernel_thread::AsKernelThread, stats::CONTEXT_SWITCH_COUNTER};
use crate::{
    prelude::*,
    sched::{SchedAttr, SchedPolicy},
};

pub(crate) mod exception;
pub(crate) mod kernel_thread;
pub(crate) mod oops;
mod softirqd;
mod stats;
pub(crate) mod task;
pub(crate) mod work_queue;

pub(crate) use self::stats::collect_context_switch_count;

pub(crate) type Tid = u32;

ostd::cpu_local_cell! {
    static WAKE_ON_SWITCH: bool = false;
}
ostd::cpu_local! {
    static MIGRATION_WAKER: SpinLock<Option<Arc<Waker>>, LocalIrqDisabled> = SpinLock::new(None);
}

fn pre_schedule_handler(irq_guard: &DisabledLocalIrqGuard) {
    let Some(task) = Task::current() else {
        return;
    };
    let Some(thread_local) = task.as_thread_local() else {
        return;
    };

    thread_local.supp_user_context().before_schedule(irq_guard);
}

fn post_schedule_handler() {
    // No races because preemption shouldn't happen in pre-/post-schedule handlers.
    CONTEXT_SWITCH_COUNTER
        .get()
        .unwrap()
        .add_on_cpu(CpuId::current_racy(), 1);

    if WAKE_ON_SWITCH.load() {
        WAKE_ON_SWITCH.store(false);
        let waker = MIGRATION_WAKER.get_on_cpu(CpuId::current_racy()).lock().take().unwrap();
        // OSTD has released the previous CPU context before invoking this hook.
        waker.wake_up();
    }

    let task = Task::current().unwrap();
    if let Some(thread_local) = task.as_thread_local() {
        let vmar = thread_local.vmar().borrow();
        if let Some(vmar) = vmar.as_ref() {
            vmar.vm_space().activate()
        }
    } else if let Some(vmar) = task
        .as_kernel_thread()
        .and_then(|kernel_thread| kernel_thread.vmar())
    {
        vmar.vm_space().activate();
    }
}

pub(super) fn init() {
    CONTEXT_SWITCH_COUNTER.call_once(PerCpuCounter::new);
    ostd::task::inject_pre_schedule_handler(pre_schedule_handler);
    ostd::task::inject_post_schedule_handler(post_schedule_handler);
    ostd::mm::fault::inject_user_page_fault_handler(exception::page_fault_handler);
}

pub(super) fn init_in_first_kthread() {
    work_queue::init_in_first_kthread();
    softirqd::init_in_first_kthread();
}

// A null snapshot denotes the full online CPU set. Restricted masks remain
// immutable until all users of the previous snapshot leave their RCU guards.
struct CpuAffinity(RcuOption<Arc<CpuSet>>);

/// An immutable mask which can outlive its RCU guard, including during user copies.
#[derive(Default)]
pub(crate) struct CpuAffinitySnapshot(Option<Arc<CpuSet>>);

fn all_cpus() -> &'static CpuSet {
    static FULL: spin::Once<CpuSet> = spin::Once::new();
    FULL.call_once(CpuSet::new_full)
}

impl CpuAffinitySnapshot {
    fn new(mask: CpuSet) -> Self {
        Self((!mask.is_full()).then(|| Arc::new(mask)))
    }
}

impl core::ops::Deref for CpuAffinitySnapshot {
    type Target = CpuSet;

    fn deref(&self) -> &CpuSet {
        match &self.0 {
            Some(mask) => mask,
            None => all_cpus(),
        }
    }
}

impl CpuAffinity {
    fn snapshot(&self) -> CpuAffinitySnapshot {
        CpuAffinitySnapshot(self.0.read().get().map(|mask| Arc::clone(&mask)))
    }

    fn with<R>(&self, f: impl FnOnce(&CpuSet) -> R) -> R {
        let read = self.0.read();
        match read.get() {
            Some(mask) => f(mask.deref_target()),
            None => f(all_cpus()),
        }
    }
}

impl core::fmt::Debug for CpuAffinity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.with(|mask| mask.fmt(f))
    }
}

#[cfg(ktest)]
mod affinity_tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn inherited_masks_remain_independent_after_updates() {
        if ostd::cpu::num_cpus() < 2 {
            return;
        }
        let cpu = CpuId::bsp();
        let initial = CpuAffinitySnapshot::new(cpu.into());
        let parent = CpuAffinity(RcuOption::new(initial.0));
        let held = parent.snapshot();
        let child = CpuAffinity(RcuOption::new(parent.snapshot().0));
        let inherited = child.snapshot();
        assert!(Arc::ptr_eq(held.0.as_ref().unwrap(), inherited.0.as_ref().unwrap()));

        parent.0.update(None);
        assert!(parent.snapshot().is_full());
        assert_eq!(child.snapshot().count(), 1);
        assert!(child.snapshot().contains(cpu));
        child.0.update(None);
        assert!(child.snapshot().is_full());
        assert_eq!(held.count(), 1);
        assert!(inherited.contains(cpu));
    }
}

/// A thread is a wrapper on top of a task.
#[derive(Debug)]
pub(crate) struct Thread {
    // Immutable part:
    //
    /// Low-level task.
    task: Weak<Task>,
    /// POSIX thread information or kernel thread information.
    data: Box<dyn Send + Sync + Any>,

    // Mutable part:
    //
    /// Thread status.
    is_exited: AtomicBool,
    /// Thread CPU affinity.
    cpu_affinity: CpuAffinity,
    affinity_writer: Mutex<()>,
    /// Thread scheduling attribute.
    sched_attr: SchedAttr,
}

impl Thread {
    /// Never call these function directly
    pub(crate) fn new(
        task: Weak<Task>,
        data: impl Send + Sync + Any,
        cpu_affinity: CpuAffinitySnapshot,
        sched_policy: SchedPolicy,
    ) -> Self {
        Thread {
            task,
            data: Box::new(data),
            is_exited: AtomicBool::new(false),
            cpu_affinity: CpuAffinity(RcuOption::new(cpu_affinity.0)),
            affinity_writer: Mutex::new(()),
            sched_attr: SchedAttr::new(sched_policy),
        }
    }

    /// Returns the current thread.
    ///
    /// This function returns `None` if the current task is not associated with
    /// a thread, or if called within the bootstrap context.
    pub(crate) fn current() -> Option<Arc<Self>> {
        Task::current()?.as_thread().cloned()
    }

    /// Returns the task associated with this thread.
    #[expect(dead_code)]
    pub(crate) fn task(&self) -> Arc<Task> {
        self.task.upgrade().unwrap()
    }

    /// Runs this thread at once.
    #[track_caller]
    pub(crate) fn run(&self) {
        self.task.upgrade().unwrap().run();
    }

    /// Returns whether the thread is exited.
    pub(crate) fn is_exited(&self) -> bool {
        self.is_exited.load(Ordering::Acquire)
    }

    pub(super) fn exit(&self) {
        self.is_exited.store(true, Ordering::Release);
    }

    pub(crate) fn cpu_affinity(&self) -> CpuAffinitySnapshot {
        self.cpu_affinity.snapshot()
    }

    pub(crate) fn with_cpu_affinity<R>(&self, f: impl FnOnce(&CpuSet) -> R) -> R {
        self.cpu_affinity.with(f)
    }

    pub(crate) fn may_enter_user(&self, guard: &DisabledLocalIrqGuard) -> bool {
        self.cpu_affinity.0.read_with(guard).is_none_or(|mask| mask.contains(guard.current_cpu()))
    }

    pub(crate) fn set_cpu_affinity(&self, mask: CpuSet, caller: &Thread) {
        let _writer = self.affinity_writer.lock();
        let old = self.cpu_affinity();
        if *old == mask {
            return;
        }
        let new = CpuAffinitySnapshot::new(mask);
        let excluded = if core::ptr::eq(self, caller) {
            None
        } else {
            let mut excluded = (*old).clone();
            for cpu in new.iter() {
                excluded.remove(cpu);
            }
            Some(excluded)
        };
        self.cpu_affinity.0.update(new.0);
        if let Some(excluded) = excluded.filter(|set| !set.is_empty()) {
            // Each old CPU either interrupts user execution or finishes a
            // kernel-side interrupt before its next IRQ-disabled entry check.
            // Keep concurrent setters ordered through this acknowledgement.
            ostd::smp::inter_processor_call(&excluded, || {}).wait();
        }
    }

    pub(crate) fn apply_current_affinity(&self) {
        loop {
            let irq = ostd::irq::disable_local();
            let current = irq.current_cpu();
            if self.may_enter_user(&irq) {
                return;
            }
            // Pick a new CPU through the regular park/wake path. The hook runs
            // on this CPU after the context switch. An intervening preemption
            // can wake us early, in which case the loop rechecks placement.
            let (waiter, waker) = Waiter::new_pair();
            let previous = MIGRATION_WAKER.get_on_cpu(current).lock().replace(waker);
            debug_assert!(previous.is_none());
            WAKE_ON_SWITCH.store(true);
            drop(irq);
            waiter.wait();
        }
    }

    pub(crate) fn sched_attr(&self) -> &SchedAttr {
        &self.sched_attr
    }

    /// Yields the execution to another thread.
    ///
    /// This method will return once the current thread is scheduled again.
    #[track_caller]
    pub(crate) fn yield_now() {
        Task::yield_now()
    }

    /// Joins the execution of the thread.
    ///
    /// This method will return after the thread exits.
    #[cfg_attr(not(ktest), expect(dead_code))]
    #[track_caller]
    pub(crate) fn join(&self) {
        while !self.is_exited() {
            Self::yield_now();
        }
    }

    /// Returns the associated data.
    pub(crate) fn data(&self) -> &(dyn Send + Sync + Any) {
        &*self.data
    }
}

/// A trait to provide the `as_thread` method for tasks.
pub(crate) trait AsThread {
    /// Returns the associated [`Thread`].
    fn as_thread(&self) -> Option<&Arc<Thread>>;
}

impl AsThread for Task {
    fn as_thread(&self) -> Option<&Arc<Thread>> {
        self.data().downcast_ref::<Arc<Thread>>()
    }
}
