// SPDX-License-Identifier: MPL-2.0

//! Completely Fair Scheduler (CFS).

#![warn(unused)]

use alloc::{boxed::Box, sync::Arc};
use core::{
    fmt,
    ops::Bound,
    sync::atomic::{AtomicU64, Ordering},
};

use ostd::{
    arch::read_tsc as sched_clock,
    cpu::{CpuId, CpuSet, PinCurrentCpu, all_cpus},
    irq::disable_local,
    sync::{LocalIrqDisabled, SpinLock},
    task::{
        AtomicCpuId, Task,
        scheduler::{
            EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags, enable_preemption_on_cpu,
            info::CommonSchedInfo, inject_scheduler,
        },
    },
    util::id_set::Id,
};
use spin::Once;

use super::{
    nice::Nice,
    stats::{SchedulerStats, set_stats_from_scheduler},
};
use crate::thread::{AsThread, Thread};

mod policy;
mod time;

mod fair;
mod idle;
mod real_time;
mod stop;

use self::policy::{SchedPolicyKind, SchedPolicyState};
pub(crate) use self::{
    policy::{LinuxSchedPolicy, SchedPolicy},
    real_time::{RealTimePolicy, RealTimePriority},
};

type SchedEntity = (Arc<Task>, Arc<Thread>);

static CLASS_SCHEDULER: Once<&'static ClassScheduler> = Once::new();

// The low bit counts the running non-idle task and each queued task contributes two.
// Leave an idle donor one runnable task for its own imminent dispatch.
fn donor_surplus(published_load: u64) -> u64 {
    published_load.saturating_sub(1) >> 1
}

/// Attempts one fair-task migration from an idle CPU. The two runqueue locks
/// are acquired in ascending CPU-ID order, and only with try_lock.
pub(crate) fn steal_a_task() -> bool {
    let Some(scheduler) = CLASS_SCHEDULER.get() else {
        return false;
    };
    let guard = disable_local();
    let cpu = guard.current_cpu();
    // Idle polling must not scan all CPUs on every iteration. Rotate through a
    // bounded window so every donor is eventually sampled, even on large hosts.
    ostd::cpu_local! {
        static NEXT_DONOR: AtomicU64 = AtomicU64::new(0);
    }
    let total = ostd::cpu::num_cpus();
    let start = NEXT_DONOR.get_on_cpu(cpu).fetch_add(16, Ordering::Relaxed) as usize;
    let Some(donor) = (0..total.min(16))
        .map(|i| CpuId::new(((start + i) % total) as u32))
        .filter(|other| *other != cpu)
        .max_by_key(|other| donor_surplus(scheduler.loads[other.as_usize()].load(Ordering::Relaxed)))
    else {
        return false;
    };
    if donor_surplus(scheduler.loads[donor.as_usize()].load(Ordering::Relaxed)) == 0 {
        return false;
    }
    let (first, second) = if cpu.as_usize() < donor.as_usize() {
        (cpu, donor)
    } else {
        (donor, cpu)
    };
    let Some(mut first_rq) = scheduler.rqs[first.as_usize()].try_lock() else {
        return false;
    };
    let Some(mut second_rq) = scheduler.rqs[second.as_usize()].try_lock() else {
        return false;
    };
    let (local, remote) = if first == cpu {
        (&mut *first_rq, &mut *second_rq)
    } else {
        (&mut *second_rq, &mut *first_rq)
    };
    if local.load_stats().queue_len != 0 || !local.load_stats().is_idle {
        return false;
    }
    if donor_surplus(remote.published_load) == 0 {
        return false;
    }
    // Stop/real-time/idle classes are not migratable through this path.
    let Some(task) = remote.fair.pick_next() else {
        return false;
    };
    let thread = task.as_thread().unwrap().clone();
    if !thread.may_enter_user(&guard) {
        remote.fair.enqueue(task, None);
        scheduler.publish_load(donor, remote);
        return false;
    }
    debug_assert_eq!(task.cpu().get(), Some(donor));
    thread
        .sched_attr()
        .fair
        .migrate_on_steal(&remote.fair, &local.fair);
    task.cpu().set_anyway(cpu);
    thread.sched_attr().set_last_cpu(cpu);
    local.enqueue_entity((task, thread), None);
    scheduler.publish_load(donor, remote);
    scheduler.publish_load(cpu, local);
    true
}

/// Registers the idle thread once it has entered its permanent polling loop.
/// Every poll yields to the local runqueue even when no donor task was found.
#[cfg(feature = "artifact_busy_poll")]
pub(crate) fn register_polling_idle() {
    let guard = disable_local();
    let scheduler = CLASS_SCHEDULER.get().unwrap();
    let mut rq = scheduler.rqs[guard.current_cpu().as_usize()].lock();
    let ((task, thread), _) = rq.current.as_ref().unwrap();
    debug_assert!(matches!(thread.sched_attr().policy(), SchedPolicy::Idle));
    rq.polling_idle = Arc::downgrade(task);
}

pub(crate) fn init() {
    let scheduler = Box::leak(Box::new(ClassScheduler::new()));

    CLASS_SCHEDULER.call_once(|| &*scheduler);

    // Inject the scheduler into the ostd for actual scheduling work.
    inject_scheduler(scheduler);

    // Set the scheduler into the system for statistics.
    // We set this after injecting the scheduler into ostd,
    // so that the loadavg statistics are updated after the scheduler is used.
    set_stats_from_scheduler(scheduler);
}

pub(crate) fn init_on_each_cpu() {
    enable_preemption_on_cpu();
}

/// Represents the middle layer between scheduling classes and generic scheduler
/// traits. It consists of all the sets of run queues for CPU cores. Other global
/// information may also be stored here.
pub(crate) struct ClassScheduler {
    /// The per-CPU runqueues.
    ///
    /// We use the `LocalIrqDisabled` marker for this spinlock to ensure local IRQs are always disabled,
    /// preventing potential deadlocks due to the fact that
    /// the runqueues may be accessed in both the task and interrupt context (L1 and L2).
    rqs: Box<[SpinLock<PerCpuClassRqSet, LocalIrqDisabled>]>,
    last_chosen_cpu: AtomicCpuId,
    loads: Box<[CpuLoad]>,
}

// Each CPU publishes only its own line; adjacent CPUs must not false-share.
#[repr(align(64))]
struct CpuLoad(AtomicU64);

impl core::ops::Deref for CpuLoad {
    type Target = AtomicU64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Represents the run queue for each CPU core. It stores a list of run queues for
/// scheduling classes in its corresponding CPU core. The current task of this CPU
/// core is also stored in this structure.
struct PerCpuClassRqSet {
    // Only the queue lock holder publishes this CPU's load.
    published_load: u64,
    #[cfg(feature = "artifact_busy_poll")]
    polling_idle: alloc::sync::Weak<Task>,
    stop: stop::StopClassRq,
    real_time: real_time::RealTimeClassRq,
    fair: fair::FairClassRq,
    idle: idle::IdleClassRq,
    current: Option<(SchedEntity, CurrentRuntime)>,
}

/// Stores the runtime information of the current task.
///
/// This is used to calculate the time slice of the current task.
///
/// This struct is independent of the current `Arc<Task>` instead encapsulating the
/// task, because the scheduling class implementations use `CurrentRuntime` and
/// `SchedAttr` only.
struct CurrentRuntime {
    start: u64,
    delta: u64,
    period_delta: u64,
}

impl CurrentRuntime {
    fn new() -> Self {
        CurrentRuntime {
            start: sched_clock(),
            delta: 0,
            period_delta: 0,
        }
    }

    fn update(&mut self) {
        let now = sched_clock();
        self.delta = now - core::mem::replace(&mut self.start, now);
        self.period_delta += self.delta;
    }
}

/// The run queue for scheduling classes (the main trait). Scheduling classes
/// should implement this trait to function as expected.
trait SchedClassRq: Send + fmt::Debug {
    /// Enqueues a task into the run queue.
    fn enqueue(&mut self, task: Arc<Task>, flags: Option<EnqueueFlags>);

    /// Returns the number of threads in the run queue.
    fn len(&self) -> usize;

    /// Checks if the run queue is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Picks the next task for running.
    fn pick_next(&mut self) -> Option<Arc<Task>>;

    /// Update the information of the current task.
    ///
    /// The return value of this method indicates whether there is another task
    /// **in this run queue** to replace the current one.
    fn update_current(&mut self, rt: &CurrentRuntime, attr: &SchedAttr, flags: UpdateFlags)
    -> bool;
}

/// The scheduling attribute for a thread.
///
/// This is used to store the scheduling policy and runtime parameters for each
/// scheduling class.
#[derive(Debug)]
pub(crate) struct SchedAttr {
    policy: SchedPolicyState,
    last_cpu: AtomicCpuId,
    real_time: real_time::RealTimeAttr,
    fair: fair::FairAttr,
}

impl SchedAttr {
    /// Constructs a new `SchedAttr` with the given scheduling policy.
    pub(crate) fn new(policy: SchedPolicy) -> Self {
        Self {
            policy: SchedPolicyState::new(policy),
            last_cpu: AtomicCpuId::default(),
            real_time: {
                let (prio, policy) = match policy {
                    SchedPolicy::RealTime { rt_prio, rt_policy } => (rt_prio.get(), rt_policy),
                    _ => (RealTimePriority::MAX.get(), Default::default()),
                };
                real_time::RealTimeAttr::new(prio, policy)
            },
            fair: fair::FairAttr::new(match policy {
                SchedPolicy::Fair(nice) => nice,
                _ => Nice::default(),
            }),
        }
    }

    /// Retrieves the current scheduling policy of the thread.
    pub(crate) fn policy(&self) -> SchedPolicy {
        self.policy.get()
    }

    fn policy_kind(&self) -> SchedPolicyKind {
        self.policy.kind()
    }

    /// Updates the scheduling policy of the thread.
    ///
    /// Specifically for real-time policies, if the new policy doesn't
    /// specify a base slice factor for RR, the old one will be kept.
    pub(crate) fn set_policy(&self, policy: SchedPolicy) {
        self.policy.set(policy, |policy| match policy {
            SchedPolicy::RealTime { rt_prio, rt_policy } => {
                self.real_time.update(rt_prio.get(), rt_policy);
            }
            SchedPolicy::Fair(nice) => self.fair.update(nice),
            _ => {}
        });
    }

    pub(crate) fn update_policy<T>(&self, f: impl FnOnce(&mut SchedPolicy) -> T) -> T {
        self.policy.update(|policy| {
            let ret = f(policy);
            match *policy {
                SchedPolicy::RealTime { rt_prio, rt_policy } => {
                    self.real_time.update(rt_prio.get(), rt_policy);
                }
                SchedPolicy::Fair(nice) => self.fair.update(nice),
                _ => {}
            }
            ret
        })
    }

    pub(crate) fn last_cpu(&self) -> Option<CpuId> {
        self.last_cpu.get()
    }

    fn set_last_cpu(&self, cpu_id: CpuId) {
        self.last_cpu.set_anyway(cpu_id);
    }
}

impl Scheduler for ClassScheduler {
    fn enqueue(&self, task: Arc<Task>, flags: EnqueueFlags) -> Option<CpuId> {
        let thread = task.as_thread()?.clone();

        let (still_in_rq, cpu) = {
            let selected_cpu_id = self.select_cpu(&thread, flags);

            if let Err(task_cpu_id) = task.cpu().set_if_is_none(selected_cpu_id) {
                debug_assert!(flags != EnqueueFlags::Spawn);
                (true, task_cpu_id)
            } else {
                (false, selected_cpu_id)
            }
        };

        let mut rq = self.rqs[cpu.as_usize()].lock();

        // Note: call set_if_is_none again to prevent a race condition.
        if still_in_rq && task.cpu().set_if_is_none(cpu).is_err() {
            return None;
        }

        // A wake can be delayed past the task's final dequeue. The successful
        // CPU reservation acquires that dequeue's terminal-state publication,
        // even if migration made the initially observed runqueue stale.
        if task.is_finished() {
            task.cpu().set_to_none();
            return None;
        }

        // Preempt if the new task has a higher priority.
        let should_preempt = rq
            .current
            .as_ref()
            .is_none_or(|((_current, rq_current_thread), _)| {
                // The polling thread will reacquire this lock during its
                // unconditional yield and observe the newly enqueued task.
                #[cfg(feature = "artifact_busy_poll")]
                if Arc::as_ptr(_current) == rq.polling_idle.as_ptr() {
                    return false;
                }
                thread.sched_attr().policy() < rq_current_thread.sched_attr().policy()
            });

        let attr = thread.sched_attr();
        if flags == EnqueueFlags::Wake && attr.last_cpu().is_some_and(|last| last != cpu) {
            attr.fair.migrate_on_wake(&rq.fair);
        }
        attr.set_last_cpu(cpu);
        rq.enqueue_entity((task, thread), Some(flags));
        self.publish_load(cpu, &mut rq);

        should_preempt.then_some(cpu)
    }

    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue)) {
        let guard = disable_local();
        let mut lock = self.rqs[guard.current_cpu().as_usize()].lock();
        f(&mut *lock);
        self.publish_load(guard.current_cpu(), &mut lock);
    }

    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue)) {
        let guard = disable_local();
        f(&*self.rqs[guard.current_cpu().as_usize()].lock())
    }
}

impl ClassScheduler {
    pub(crate) fn new() -> Self {
        let class_rq = |cpu| {
            SpinLock::new(PerCpuClassRqSet {
                published_load: 0,
                #[cfg(feature = "artifact_busy_poll")]
                polling_idle: alloc::sync::Weak::new(),
                stop: stop::StopClassRq::new(),
                real_time: real_time::RealTimeClassRq::new(cpu),
                fair: fair::FairClassRq::new(cpu),
                idle: idle::IdleClassRq::new(),
                current: None,
            })
        };
        ClassScheduler {
            rqs: all_cpus().map(class_rq).collect(),
            last_chosen_cpu: AtomicCpuId::default(),
            loads: all_cpus().map(|_| CpuLoad(AtomicU64::new(0))).collect(),
        }
    }

    // Published under the owning runqueue lock after every mutation. Readers
    // use approximate load only for placement/statistics, never for ownership.
    fn publish_load(&self, cpu: CpuId, rq: &mut PerCpuClassRqSet) {
        let PerCpuLoadStats { queue_len, is_idle } = rq.load_stats();
        let value = ((queue_len as u64) << 1) | u64::from(!is_idle);
        // Idle yields frequently revisit the same state. Compare under the
        // queue lock without touching the cache line scanned by other CPUs.
        if rq.published_load != value {
            self.loads[cpu.as_usize()].store(value, Ordering::Relaxed);
            rq.published_load = value;
        }
    }

    // TODO: Implement a better algorithm and replace the current naive implementation.
    fn select_cpu(&self, thread: &Thread, _flags: EnqueueFlags) -> CpuId {
        thread.with_cpu_affinity(|affinity| {
            if let Some(last_cpu) = thread.sched_attr().last_cpu()
                && affinity.contains(last_cpu)
            {
                return last_cpu;
            }

            let guard = disable_local();
            let selected =
                self.least_loaded_cpu(affinity, self.last_chosen_cpu.get(), guard.current_cpu());
            self.last_chosen_cpu.set_anyway(selected);
            selected
        })
    }

    fn least_loaded_cpu(&self, affinity: &CpuSet, after: Option<CpuId>, fallback: CpuId) -> CpuId {
        // Starting after the final CPU gives ascending order on the first placement.
        let after = after.unwrap_or_else(|| CpuId::new((self.loads.len() - 1) as u32));
        let mut selected = fallback;
        let mut minimum_load = u32::MAX;
        for candidate in Self::cycle_after(after, affinity) {
            let snapshot = self.loads[candidate.as_usize()].load(Ordering::Relaxed);
            let load = (snapshot >> 1) as u32 + (snapshot & 1) as u32;
            // No later queue can improve on zero. The first eligible idle CPU
            // is already the winner under the rotating tie order.
            if load == 0 {
                return candidate;
            }
            if load < minimum_load {
                minimum_load = load;
                selected = candidate;
            }
        }
        selected
    }

    /// Returns a cycling iterator over the CPUs in the [`CpuSet`], starting *after*
    /// the given [`CpuId`].
    ///
    /// The iteration order is ascending up to the wrapping point, after which it
    /// continues from the first CPU in the set in ascending order again.
    ///
    /// If the given [`CpuId`] is in the set, it will be the last element yielded.
    fn cycle_after(cpu: CpuId, cpu_set: &CpuSet) -> impl Iterator<Item = CpuId> + '_ {
        cpu_set
            .iter_in((Bound::Excluded(cpu), Bound::Unbounded))
            .chain(cpu_set.iter_in(..=cpu))
    }
}

impl PerCpuClassRqSet {
    fn pick_next_entity(&mut self) -> Option<SchedEntity> {
        (self.stop.pick_next())
            .or_else(|| self.real_time.pick_next())
            .or_else(|| self.fair.pick_next())
            .or_else(|| self.idle.pick_next())
            .and_then(|task| {
                let thread = task.as_thread()?.clone();
                Some((task, thread))
            })
    }

    fn enqueue_entity(&mut self, (task, thread): SchedEntity, flags: Option<EnqueueFlags>) {
        match thread.sched_attr().policy_kind() {
            SchedPolicyKind::Stop => self.stop.enqueue(task, flags),
            SchedPolicyKind::RealTime => self.real_time.enqueue(task, flags),
            SchedPolicyKind::Fair => self.fair.enqueue(task, flags),
            SchedPolicyKind::Idle => self.idle.enqueue(task, flags),
        }
    }

    fn load_stats(&self) -> PerCpuLoadStats {
        let queue_len = (self.stop.len() + self.real_time.len() + self.fair.len()) as u32;
        let is_idle = match &self.current {
            Some(((_, thread), _)) => thread.sched_attr().policy_kind() == SchedPolicyKind::Idle,
            None => true,
        };
        PerCpuLoadStats { queue_len, is_idle }
    }
}

impl LocalRunQueue for PerCpuClassRqSet {
    fn current(&self) -> Option<&Arc<Task>> {
        self.current.as_ref().map(|((task, _), _)| task)
    }

    fn try_pick_next(&mut self) -> Option<&Arc<Task>> {
        self.pick_next_entity().and_then(|next| {
            // We guarantee that a task can appear at once in a `PerCpuClassRqSet`. So, the `next` cannot be the same
            // as the current task here.
            if let Some((old, _)) = self.current.replace((next, CurrentRuntime::new())) {
                self.enqueue_entity(old, None);
            }
            self.current.as_ref().map(|((task, _), _)| task)
        })
    }

    fn update_current(&mut self, flags: UpdateFlags) -> bool {
        let (should_preempt, mut lookahead) = if let Some(((_, cur), rt)) = &mut self.current {
            rt.update();
            let attr = &cur.sched_attr();

            match attr.policy_kind() {
                SchedPolicyKind::Stop => (self.stop.update_current(rt, attr, flags), 0),
                SchedPolicyKind::RealTime => (self.real_time.update_current(rt, attr, flags), 1),
                SchedPolicyKind::Fair => (self.fair.update_current(rt, attr, flags), 2),
                SchedPolicyKind::Idle => (self.idle.update_current(rt, attr, flags), 3),
            }
        } else {
            (false, 4)
        };

        if matches!(flags, UpdateFlags::Wait | UpdateFlags::Exit) {
            lookahead = 4;
        }

        should_preempt
            || (lookahead >= 1 && !self.stop.is_empty())
            || (lookahead >= 2 && !self.real_time.is_empty())
            || (lookahead >= 3 && !self.fair.is_empty())
            || (lookahead >= 4 && !self.idle.is_empty())
    }

    fn dequeue_current(&mut self) -> Option<Arc<Task>> {
        self.current.take().map(|((cur_task, thread), _)| {
            thread.sched_attr().fair.remember_departure(&self.fair);
            cur_task.schedule_info().cpu.set_to_none();
            cur_task
        })
    }
}

/// Holds per-CPU load information.
struct PerCpuLoadStats {
    /// The length of the run queue (excluding the idle task).
    queue_len: u32,
    /// If the CPU is currently idle.
    ///
    /// A CPU is said to be idle when it is running the idle task, or it is not
    /// running any task at all. The latter case is very unlikely to happen
    /// (almost a bug if it happens) as the idle task should always be runnable.
    is_idle: bool,
}

impl SchedulerStats for ClassScheduler {
    fn nr_queued_and_running(&self) -> (u32, u32) {
        self.loads.iter().fold((0, 0), |(queued, running), load| {
            let value = load.load(Ordering::Relaxed);
            (queued + (value >> 1) as u32, running + (value & 1) as u32)
        })
    }
}

impl Default for ClassScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(ktest)]
mod placement_tests {
    use alloc::vec::Vec;

    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn donor_leaves_one_task_for_idle_dispatch() {
        for queued in 0u64..4 {
            assert_eq!(donor_surplus(queued << 1), queued.saturating_sub(1));
            assert_eq!(donor_surplus((queued << 1) | 1), queued);
        }
    }

    #[ktest]
    fn queue_load_tracks_enqueue_and_drain() {
        let scheduler = ClassScheduler::new();
        let cpu = CpuId::bsp();
        let task = Arc::new(ostd::task::TaskOptions::new(|| {}).build().unwrap());
        let published = &scheduler.loads[cpu.as_usize()];
        let mut rq = scheduler.rqs[cpu.as_usize()].lock();

        assert_eq!(published.load(Ordering::Relaxed), 0);
        rq.stop.enqueue(task, None);
        scheduler.publish_load(cpu, &mut rq);
        assert_eq!(published.load(Ordering::Relaxed), 2);
        assert_eq!(rq.published_load, 2);
        scheduler.publish_load(cpu, &mut rq);
        assert_eq!(published.load(Ordering::Relaxed), 2);
        let task = rq.stop.pick_next().unwrap();
        scheduler.publish_load(cpu, &mut rq);
        assert_eq!(published.load(Ordering::Relaxed), 0);
        assert_eq!(rq.published_load, 0);
        drop(rq);
        drop(task);
    }

    #[ktest]
    fn first_idle_preserves_restricted_and_busy_ties() {
        let scheduler = ClassScheduler::new();
        let cpus: Vec<_> = all_cpus().take(4).collect();
        let count = cpus.len();
        for mut pattern in 0..3_usize.pow(count as u32) {
            let mut scores = Vec::new();
            for cpu in &cpus {
                let load = pattern % 3;
                pattern /= 3;
                // Idle, running, or running with a queued task.
                scheduler.loads[cpu.as_usize()].store([0, 1, 3][load], Ordering::Relaxed);
                scores.push(load);
            }
            for mask in 0..1_usize << count {
                let mut affinity = CpuSet::new_empty();
                for (i, &cpu) in cpus.iter().enumerate() {
                    if mask & (1 << i) != 0 {
                        affinity.add(cpu);
                    }
                }
                for prior in 0..=count {
                    let after = cpus.get(prior).copied();
                    let start = after.map_or(0, |cpu| cpu.as_usize() + 1);
                    let expected = (0..count)
                        .map(|i| (start + i) % count)
                        .filter(|&i| mask & (1 << i) != 0)
                        .min_by_key(|&i| scores[i])
                        .map_or(cpus[0], |i| cpus[i]);
                    assert_eq!(
                        scheduler.least_loaded_cpu(&affinity, after, cpus[0]),
                        expected
                    );
                }
            }
        }
    }
}
