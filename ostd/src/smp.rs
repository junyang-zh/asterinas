// SPDX-License-Identifier: MPL-2.0

//! Symmetric Multi-Processing (SMP) support.
//!
//! This module provides a way to execute code on other processors via inter-
//! processor interrupts.
//!
//! Callers issue work with [`inter_processor_call`]. Remote calls are queued for
//! interrupt-context execution and return a [`PendingIpis`] handle that can be
//! waited on when the caller needs completion.

use alloc::{boxed::Box, collections::VecDeque};
use core::sync::atomic::{AtomicBool, Ordering};

use spin::Once;

use crate::{
    arch::{irq::HwCpuId, trap::TrapFrame},
    cpu::{CpuSet, PinCurrentCpu},
    cpu_local, irq,
    mm::tlb::OpsStack,
    sync::SpinLock,
    util::id_set::Id,
};

/// Executes a function on other processors.
///
/// The provided function `call_fn` will be executed on all target processors
/// specified by `targets`. It can also be executed on the current processor.
/// The function should be short and non-blocking, as it will be executed in
/// interrupt context with interrupts disabled.
///
/// The function `call_fn` will be executed asynchronously on the target
/// processors. However, if called on the current processor, it will be
/// synchronous.
///
/// The returned [`PendingIpis`] can be used to wait until all remote target
/// processors have handled IPIs for this call.
///
/// # Panics
///
/// This function will panic if a hardware error occurs while sending an IPI to
/// a remote processor.
pub fn inter_processor_call(targets: &CpuSet, call_fn: fn()) -> PendingIpis {
    let ipi_sender = IPI_SENDER.get().unwrap();
    ipi_sender.inter_processor_call(targets, call_fn)
}

/// Pending remote inter-processor calls.
pub struct PendingIpis {
    cpus: CpuSet,
}

impl PendingIpis {
    pub(crate) fn new_empty() -> Self {
        Self {
            cpus: CpuSet::new_empty(),
        }
    }

    fn add(&mut self, cpu_id: crate::cpu::CpuId) {
        self.cpus.add(cpu_id);
    }

    pub(crate) fn extend(&mut self, other: &Self) {
        for cpu_id in other.cpus.iter() {
            self.add(cpu_id);
        }
    }

    /// Waits until all pending remote processors have handled their IPIs.
    ///
    /// # Panics
    ///
    /// This method panics if local IRQs are disabled. Waiting for remote IPIs
    /// with local IRQs disabled can deadlock if one of the remote processors is
    /// also waiting for this processor to handle an IPI.
    pub fn wait(&self) {
        assert!(
            crate::arch::irq::is_local_enabled(),
            "waiting for remote inter-processor calls with IRQs disabled"
        );

        for cpu_id in self.cpus.iter() {
            // Wait until there are no pending IPIs on the target CPU.
            //
            // Note that if new IPIs arrive to that CPU in the meantime, we
            // will also wait for them. This is fine because there usually
            // aren't too many IPIs in common cases.
            while HAS_PENDING_IPIS
                .get_on_cpu(cpu_id)
                .0
                .load(Ordering::Acquire)
            {
                core::hint::spin_loop();
            }
        }
    }
}

/// A sender that carries necessary information to send inter-processor interrupts.
///
/// The purpose of exporting this type is to enable the users to check whether
/// [`IPI_SENDER`] has been initialized.
pub(crate) struct IpiSender {
    hw_cpu_ids: Box<[HwCpuId]>,
    #[cfg(target_arch = "x86_64")]
    clustered: bool,
}

/// The [`IpiSender`] singleton.
pub(crate) static IPI_SENDER: Once<IpiSender> = Once::new();

impl IpiSender {
    /// Executes a function on other processors.
    ///
    /// See [`inter_processor_call`] for details. The purpose of exporting this
    /// method is to enable callers to check whether [`IPI_SENDER`] has been
    /// initialized.
    pub(crate) fn inter_processor_call(&self, targets: &CpuSet, call_fn: fn()) -> PendingIpis {
        self.submit::<false>(
            targets,
            |queue| queue.callbacks.push_back(Callback::Call(call_fn)),
            call_fn,
        )
    }

    /// The caller handles its own CPU after submitting the remote invalidations.
    pub(crate) fn send_tlb_flush(&self, targets: &CpuSet, ops: &OpsStack) -> PendingIpis {
        self.submit::<true>(
            targets,
            |queue| {
                if queue.tlb_ops.is_empty() {
                    queue.callbacks.push_back(Callback::FlushTlb);
                }
                queue.tlb_ops.push_from(ops);
            },
            || unreachable!("the origin handles its local TLB separately"),
        )
    }

    fn submit<const DEFER_BUSY: bool>(
        &self,
        targets: &CpuSet,
        enqueue: impl Fn(&mut CallQueue),
        local: impl FnOnce(),
    ) -> PendingIpis {
        let irq_guard = irq::disable_local();
        let this_cpu_id = irq_guard.current_cpu();

        let mut call_on_self = false;
        let mut pending_ipis = PendingIpis::new_empty();
        let mut kicks = CpuSet::new_empty();
        let mut publish = |cpu_id, queue: &mut CallQueue, pending: &mut PendingIpis| {
            if queue.callbacks.is_empty() {
                kicks.add(cpu_id);
                HAS_PENDING_IPIS
                    .get_on_cpu(cpu_id)
                    .0
                    .store(true, Ordering::Release);
            }
            enqueue(queue);
            pending.add(cpu_id);
        };

        let mut deferred = false;
        for cpu_id in targets.iter() {
            if cpu_id == this_cpu_id {
                call_on_self = true;
                continue;
            }
            let queue = CALL_QUEUES.get_on_cpu(cpu_id);
            let mut guard = if DEFER_BUSY {
                let Some(guard) = queue.try_lock() else {
                    deferred = true;
                    continue;
                };
                guard
            } else {
                queue.lock()
            };
            publish(cpu_id, &mut guard, &mut pending_ipis);
        }
        if deferred {
            // Every target receives the invalidation before notifications are sent.
            // The existing completion mask identifies queues already populated.
            for cpu_id in targets.iter() {
                if cpu_id != this_cpu_id && !pending_ipis.cpus.contains(cpu_id) {
                    let mut guard = CALL_QUEUES.get_on_cpu(cpu_id).lock();
                    publish(cpu_id, &mut guard, &mut pending_ipis);
                }
            }
        }
        let remote_ids = kicks.iter().map(|cpu| self.hw_cpu_ids[cpu.as_usize()]);
        #[cfg(target_arch = "x86_64")]
        crate::arch::irq::send_ipis(remote_ids, self.clustered, &irq_guard);
        #[cfg(not(target_arch = "x86_64"))]
        for id in remote_ids {
            crate::arch::irq::send_ipi(id, &irq_guard)
                .expect("failed to send inter-processor interrupt");
        }
        if call_on_self {
            // Execute the function synchronously.
            local();
        }
        pending_ipis
    }
}

// Waiters on other CPUs poll this byte until all callbacks complete. Keep
// writes to the call queue and other CPU-local state off its cache line.
#[repr(align(64))]
struct PendingFlag(AtomicBool);

enum Callback {
    Call(fn()),
    FlushTlb,
}

struct CallQueue {
    callbacks: VecDeque<Callback>,
    tlb_ops: OpsStack,
}

cpu_local! {
    static CALL_QUEUES: SpinLock<CallQueue> = SpinLock::new(CallQueue {
        callbacks: VecDeque::new(),
        tlb_ops: OpsStack::new(),
    });
    static HAS_PENDING_IPIS: PendingFlag = PendingFlag(AtomicBool::new(false));
}

/// Handles inter-processor calls.
///
/// # Safety
///
/// This function must be called from an IRQ handler that can be triggered by
/// inter-processor interrupts.
pub(crate) unsafe fn do_inter_processor_call(_trapframe: &TrapFrame) {
    // No races because we are in IRQs.
    let this_cpu_id = crate::cpu::CpuId::current_racy();

    let queue = CALL_QUEUES.get_on_cpu(this_cpu_id);
    let (mut batch, mut tlb_ops) = {
        let mut queued = queue.lock();
        let callbacks = core::mem::take(&mut queued.callbacks);
        let ops = if queued.tlb_ops.is_empty() {
            None
        } else {
            Some(core::mem::replace(&mut queued.tlb_ops, OpsStack::new()))
        };
        (callbacks, ops)
    };
    // Once detached, only this IRQ handler owns these operations and frames.
    // A new producer installs its own marker and notification in the next batch.
    while let Some(callback) = batch.pop_front() {
        match callback {
            Callback::Call(call) => call(),
            Callback::FlushTlb => tlb_ops
                .as_mut()
                .expect("missing TLB batch")
                .flush_on_remote(),
        }
    }
    let mut next = queue.lock();
    if next.callbacks.is_empty() {
        next.callbacks = batch;
        HAS_PENDING_IPIS
            .get_on_cpu(this_cpu_id)
            .0
            .store(false, Ordering::Release);
    }
}

pub(super) fn init() {
    IPI_SENDER.call_once(|| {
        let hw_cpu_ids = crate::boot::smp::construct_hw_cpu_id_mapping();
        IpiSender {
            #[cfg(target_arch = "x86_64")]
            clustered: crate::arch::irq::supports_cluster_delivery(&hw_cpu_ids),
            hw_cpu_ids,
        }
    });
}

#[cfg(ktest)]
mod test {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::{
        cpu::{self, PinCurrentCpu},
        prelude::ktest,
        task,
    };

    static IPI_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);

    fn count_ipi_call() {
        IPI_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    #[ktest]
    fn pending_ipis_waits_for_all_cpus() {
        let before = IPI_CALL_COUNT.load(Ordering::Relaxed);

        super::inter_processor_call(&cpu::CpuSet::new_full(), count_ipi_call).wait();

        assert_eq!(
            IPI_CALL_COUNT.load(Ordering::Relaxed) - before,
            cpu::num_cpus()
        );
    }

    #[ktest]
    fn inter_processor_call_runs_on_current_cpu() {
        let preempt_guard = task::disable_preempt();
        let before = IPI_CALL_COUNT.load(Ordering::Relaxed);

        super::inter_processor_call(
            &cpu::CpuSet::from(preempt_guard.current_cpu()),
            count_ipi_call,
        )
        .wait();

        assert_eq!(IPI_CALL_COUNT.load(Ordering::Relaxed) - before, 1);
    }

    #[ktest]
    fn pending_ipis_waits_for_remote_cpu() {
        if cpu::num_cpus() < 2 {
            return;
        }

        let preempt_guard = task::disable_preempt();
        let target_cpu = cpu::all_cpus()
            .find(|cpu_id| *cpu_id != preempt_guard.current_cpu())
            .unwrap();
        let before = IPI_CALL_COUNT.load(Ordering::Relaxed);

        super::inter_processor_call(&cpu::CpuSet::from(target_cpu), count_ipi_call).wait();

        assert_eq!(IPI_CALL_COUNT.load(Ordering::Relaxed) - before, 1);
    }

    #[ktest]
    fn calls_submitted_during_a_callback_complete_in_the_next_batch() {
        use core::sync::atomic::AtomicBool;

        static ENTERED: AtomicBool = AtomicBool::new(false);
        static CONTINUE: AtomicBool = AtomicBool::new(false);
        static FINISHED: AtomicBool = AtomicBool::new(false);
        static NEXT_BATCH: AtomicBool = AtomicBool::new(false);

        fn first() {
            ENTERED.store(true, Ordering::Release);
            for _ in 0..10_000_000 {
                if CONTINUE.load(Ordering::Acquire) {
                    FINISHED.store(true, Ordering::Release);
                    break;
                }
                core::hint::spin_loop();
            }
        }
        fn second() {
            NEXT_BATCH.store(FINISHED.load(Ordering::Acquire), Ordering::Release);
        }
        let pin = task::disable_preempt();
        let Some(other) = cpu::all_cpus().find(|&id| id != pin.current_cpu()) else {
            return;
        };
        let targets = cpu::CpuSet::from(other);
        let mut pending = super::inter_processor_call(&targets, first);
        while !ENTERED.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        pending.extend(&super::inter_processor_call(&targets, second));
        CONTINUE.store(true, Ordering::Release);
        pending.wait();
        assert!(NEXT_BATCH.load(Ordering::Acquire));
    }

    #[ktest]
    fn busy_destination_does_not_delay_other_publications() {
        use core::sync::atomic::AtomicBool;

        static TARGETS: spin::Once<cpu::CpuSet> = spin::Once::new();
        static ENTERED: AtomicBool = AtomicBool::new(false);
        static PUBLISHED: AtomicUsize = AtomicUsize::new(0);
        static EXECUTED: AtomicUsize = AtomicUsize::new(0);

        fn execute() {
            EXECUTED.fetch_add(1, Ordering::Relaxed);
        }
        fn send() {
            ENTERED.store(true, Ordering::Release);
            let _ = super::IPI_SENDER.get().unwrap().submit::<true>(
                TARGETS.get().unwrap(),
                |queue| {
                    queue.callbacks.push_back(super::Callback::Call(execute));
                    PUBLISHED.fetch_add(1, Ordering::Release);
                },
                || unreachable!(),
            );
        }
        if cpu::num_cpus() < 4 {
            return;
        }
        let pin = task::disable_preempt();
        let mut peers = cpu::all_cpus().filter(|id| *id != pin.current_cpu());
        let first = peers.next().unwrap();
        let second = peers.next().unwrap();
        let origin = peers.next().unwrap();
        let targets = TARGETS.call_once(|| {
            let mut targets = cpu::CpuSet::from(first);
            targets.add(second);
            targets
        });

        let irq = crate::irq::disable_local();
        let held = super::CALL_QUEUES.get_on_cpu(first).lock();
        let sender = super::inter_processor_call(&cpu::CpuSet::from(origin), send);
        while !ENTERED.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let observed = (0..2_000_000).any(|_| {
            core::hint::spin_loop();
            PUBLISHED.load(Ordering::Acquire) == 1
        });
        drop(held);
        drop(irq);
        sender.wait();
        super::inter_processor_call(targets, || {}).wait();
        assert!(observed);
        assert_eq!(PUBLISHED.load(Ordering::Acquire), 2);
        assert_eq!(EXECUTED.load(Ordering::Acquire), 2);
    }

    #[ktest]
    fn synchronous_flushes_share_one_queued_marker() {
        use core::sync::atomic::AtomicBool;

        use crate::mm::tlb::{TlbFlushOp, TlbFlusher};

        static ENTERED: AtomicBool = AtomicBool::new(false);
        static RELEASE: AtomicBool = AtomicBool::new(false);
        fn hold() {
            ENTERED.store(true, Ordering::Release);
            while !RELEASE.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
        }

        let pin = task::disable_preempt();
        let Some(other) = cpu::all_cpus().find(|&id| id != pin.current_cpu()) else {
            return;
        };
        let cpus = cpu::CpuSet::from(other);
        let active = cpu::AtomicCpuSet::new(cpus.clone());
        ENTERED.store(false, Ordering::Relaxed);
        RELEASE.store(false, Ordering::Relaxed);
        let hold_call = super::inter_processor_call(&cpus, hold);
        while !ENTERED.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let mut first = TlbFlusher::new(&active, task::disable_preempt());
        let mut second = TlbFlusher::new(&active, task::disable_preempt());
        first.issue_tlb_flush(TlbFlushOp::for_single(0x1000));
        first.dispatch_tlb_flush();
        let before = IPI_CALL_COUNT.load(Ordering::Relaxed);
        let between = super::inter_processor_call(&cpus, count_ipi_call);
        second.issue_tlb_flush(TlbFlushOp::for_single(0x2000));
        second.dispatch_tlb_flush();
        let (markers, has_ops) = {
            let queue = super::CALL_QUEUES.get_on_cpu(other).lock();
            (
                queue
                    .callbacks
                    .iter()
                    .filter(|cb| matches!(cb, super::Callback::FlushTlb))
                    .count(),
                !queue.tlb_ops.is_empty(),
            )
        };
        RELEASE.store(true, Ordering::Release);
        first.sync_tlb_flush();
        second.sync_tlb_flush();
        between.wait();
        hold_call.wait();
        assert_eq!(markers, 1);
        assert!(has_ops);
        assert_eq!(IPI_CALL_COUNT.load(Ordering::Relaxed), before + 1);
    }

    #[ktest]
    fn pending_ipis_can_be_extended() {
        if cpu::num_cpus() < 2 {
            return;
        }

        let preempt_guard = task::disable_preempt();
        let target_cpu = cpu::all_cpus()
            .find(|cpu_id| *cpu_id != preempt_guard.current_cpu())
            .unwrap();
        let target_cpus = cpu::CpuSet::from(target_cpu);
        let before = IPI_CALL_COUNT.load(Ordering::Relaxed);

        let mut pending_ipis = super::PendingIpis::new_empty();
        pending_ipis.extend(&super::inter_processor_call(&target_cpus, count_ipi_call));
        pending_ipis.extend(&super::inter_processor_call(&target_cpus, count_ipi_call));
        pending_ipis.wait();

        assert_eq!(IPI_CALL_COUNT.load(Ordering::Relaxed) - before, 2);
    }
}
