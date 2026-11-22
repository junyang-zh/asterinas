// SPDX-License-Identifier: MPL-2.0

use alloc::collections::VecDeque;
use core::sync::atomic::{
    AtomicBool, AtomicU64,
    Ordering::{AcqRel, Acquire, Relaxed, Release},
};

use crate::{
    cpu::{PinCurrentCpu, num_cpus},
    prelude::*,
    sync::SpinLock,
    task::disable_preempt,
};

/// Tracks the CPUs that must pass a quiescent state before callbacks may run.
pub(super) struct RcuMonitor {
    is_monitoring: AtomicBool,
    state: SpinLock<State>,
    retirements: Box<[RetirementQueue]>,
    pending: PendingReports,
}

type Callbacks = VecDeque<Box<dyn FnOnce() + Send + 'static>>;

// Separate producers on different groups of CPUs during frame retirement.
#[repr(align(64))]
struct RetirementQueue(SpinLock<Callbacks>);

#[derive(Default)]
struct State {
    current: Callbacks,
    next: Callbacks,
    retired: Vec<Callbacks>,
}

impl State {
    fn is_idle(&self) -> bool {
        self.current.is_empty() && self.retired.is_empty()
    }
}

struct PendingReports {
    words: Box<[PendingWord]>,
    last_mask: u64,
}

// Separate groups of CPUs should not invalidate one another's reports.
#[repr(align(64))]
struct PendingWord(AtomicU64);

impl PendingReports {
    fn new(cpus: usize) -> Self {
        assert!(cpus > 0);
        let words = (0..cpus.div_ceil(64))
            .map(|_| PendingWord(AtomicU64::new(0)))
            .collect();
        let last_mask = u64::MAX >> (63 - (cpus - 1) % 64);
        Self { words, last_mask }
    }

    // Called with the state lock held, after installing the current callbacks.
    fn start(&self) {
        let (last, full) = self.words.split_last().unwrap();
        for word in full {
            word.0.store(u64::MAX, Release);
        }
        last.0.store(self.last_mask, Release);
    }

    // Only the CPU clearing a word's last pending bit checks for completion.
    fn report(&self, cpu: usize) -> bool {
        let word = &self.words[cpu / 64].0;
        let bit = 1 << (cpu % 64);
        if word.load(Relaxed) & bit == 0 {
            return false;
        }
        // The caller stays quiescent and pinned through this RMW. If a
        // restart intervened after the hint load, this reports the CPU's
        // current quiescent state against the newly published word.
        word.fetch_and(!bit, AcqRel) == bit
    }

    fn is_complete(&self) -> bool {
        // The state lock excludes restarts during this scan. The acquire
        // loads observe all quiescent reports via each word's RMW sequence.
        self.words.iter().all(|word| word.0.load(Acquire) == 0)
    }
}

impl RcuMonitor {
    pub(super) fn new() -> Self {
        Self {
            is_monitoring: AtomicBool::new(false),
            state: SpinLock::new(State::default()),
            retirements: (0..num_cpus().min(16))
                .map(|_| RetirementQueue(SpinLock::new(Callbacks::new())))
                .collect(),
            pending: PendingReports::new(num_cpus()),
        }
    }

    pub(super) unsafe fn finish_grace_period(&self) {
        if !self.is_monitoring.load(Relaxed) {
            return;
        }

        let pin = disable_preempt();
        if !self.pending.report(u32::from(pin.current_cpu()) as usize) {
            return;
        }

        drop(pin);
        self.run_completed_callbacks();
    }

    fn run_completed_callbacks(&self) {
        let (callbacks, retired) = {
            let mut state = self.state.disable_irq().lock();
            // A different group's reporter may already have drained this
            // period and started the next. Check the actual current state.
            if state.is_idle() || !self.pending.is_complete() {
                return;
            }
            let done = (
                core::mem::take(&mut state.current),
                core::mem::take(&mut state.retired),
            );
            self.start_next(&mut state);
            done
        };

        for f in callbacks.into_iter().chain(retired.into_iter().flatten()) {
            f();
        }
    }

    pub(super) fn after_grace_period<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let mut state = self.state.disable_irq().lock();
        state.next.push_back(Box::new(f));
        if state.is_idle() {
            self.start_next(&mut state);
        }
    }

    // Only independent destructors use these queues. Ordered RCU callbacks
    // continue to use the single FIFO in State.
    pub(super) fn retire_independently<F: FnOnce() + Send + 'static>(&self, f: F) {
        let callback = Box::new(f);
        let cpu = u32::from(crate::cpu::CpuId::current_racy()) as usize;
        let index = cpu * self.retirements.len() / num_cpus();
        let first = {
            let mut queue = self.retirements[index].0.disable_irq().lock();
            let empty = queue.is_empty();
            queue.push_back(callback);
            empty
        };
        if first {
            // A newly filled queue may have missed the last drain. Acquire
            // state only after releasing the queue, including when called in IRQ.
            let mut state = self.state.disable_irq().lock();
            if state.is_idle() {
                self.start_next(&mut state);
            }
        }
    }

    fn start_next(&self, state: &mut State) {
        state.current = core::mem::take(&mut state.next);
        // Collect before requesting any quiescent reports for this period.
        // A producer that arrives after its queue is detached remains queued
        // for a full subsequent period and owns the empty-to-filled check.
        for retirement in &self.retirements {
            let mut queue = retirement.0.disable_irq().lock();
            if !queue.is_empty() {
                state.retired.push(core::mem::take(&mut *queue));
            }
        }
        if state.is_idle() {
            self.is_monitoring.store(false, Relaxed);
        } else {
            self.pending.start();
            self.is_monitoring.store(true, Relaxed);
        }
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{
        cpu::{CpuSet, all_cpus},
        smp::inter_processor_call,
        task::atomic_mode::might_sleep,
    };

    #[ktest]
    fn remote_reports_wait_for_a_pinned_reader() {
        static MONITOR: spin::Once<RcuMonitor> = spin::Once::new();

        fn report_remote() {
            // SAFETY: Only the test task can read from this private domain.
            // The target set excludes the CPU on which it holds its read pin.
            unsafe { MONITOR.get().unwrap().finish_grace_period() };
        }

        let monitor = MONITOR.call_once(RcuMonitor::new);
        for value in 0..64 {
            let reader = disable_preempt();
            let mut others = CpuSet::new_full();
            others.remove(reader.current_cpu());
            let object = Arc::new(value);
            let observed = Arc::downgrade(&object);
            monitor.after_grace_period(move || {
                might_sleep();
                drop(object);
            });
            inter_processor_call(&others, report_remote).wait();
            assert_eq!(observed.upgrade().as_deref(), Some(&value));
            drop(reader);
            // SAFETY: No reader in the test domain remains on this CPU.
            unsafe { monitor.finish_grace_period() };
            assert!(observed.upgrade().is_none());
        }
    }

    #[ktest]
    fn every_cpu_must_report_again_after_restart() {
        for cpus in [1, 63, 64, 65, 384] {
            let pending = PendingReports::new(cpus);
            for _ in 0..3 {
                pending.start();
                for cpu in (0..cpus).rev() {
                    assert!(!pending.is_complete());
                    assert_eq!(pending.report(cpu), cpu % 64 == 0);
                    assert!(!pending.report(cpu));
                }
                assert!(pending.is_complete());
            }
        }
    }

    #[ktest]
    fn independent_retirements_cross_a_full_grace_period() {
        static MONITOR: spin::Once<RcuMonitor> = spin::Once::new();
        static COMPLETED: AtomicU64 = AtomicU64::new(0);
        fn submit() {
            for _ in 0..8 {
                MONITOR.get().unwrap().retire_independently(|| {
                    might_sleep();
                    COMPLETED.fetch_add(1, Relaxed);
                });
            }
        }
        let monitor = MONITOR.call_once(RcuMonitor::new);
        let first = Arc::new(AtomicU64::new(0));
        let after = first.clone();
        monitor.retire_independently(move || {
            after.fetch_add(1, Relaxed);
        });
        let pin = disable_preempt();
        let local = pin.current_cpu();
        inter_processor_call(&CpuSet::new_full(), submit).wait();
        for cpu in all_cpus().filter(|&cpu| cpu != local) {
            monitor.pending.report(u32::from(cpu) as usize);
        }
        monitor.run_completed_callbacks();
        assert_eq!(first.load(Relaxed), 0);
        drop(pin);
        // The captured CPU has now left the private read section.
        monitor.pending.report(u32::from(local) as usize);
        monitor.run_completed_callbacks();
        assert_eq!(first.load(Relaxed), 1);
        assert_eq!(COMPLETED.load(Relaxed), 0);
        for cpu in all_cpus() {
            monitor.pending.report(u32::from(cpu) as usize);
        }
        monitor.run_completed_callbacks();
        assert_eq!(COMPLETED.load(Relaxed), num_cpus() as u64 * 8);
        // Exercise the independent empty-to-filled transition again after idle.
        monitor.retire_independently(|| {
            COMPLETED.fetch_add(1, Relaxed);
        });
        for cpu in all_cpus() {
            monitor.pending.report(u32::from(cpu) as usize);
        }
        monitor.run_completed_callbacks();
        assert_eq!(COMPLETED.load(Relaxed), num_cpus() as u64 * 8 + 1);
    }

    #[ktest]
    fn queued_callbacks_wait_for_the_next_period() {
        let monitor = RcuMonitor::new();
        let calls = Arc::new(AtomicU64::new(0));
        for expected in 0..2 {
            let calls = calls.clone();
            monitor.after_grace_period(move || {
                might_sleep();
                assert_eq!(calls.fetch_add(1, Relaxed), expected);
            });
        }
        for expected in 1..=2 {
            // There are no protected readers on this private monitor.
            // Simulate all quiescent reports, then run the last reporter's
            // completion path without an outer CPU pin.
            for cpu in all_cpus() {
                monitor.pending.report(u32::from(cpu) as usize);
            }
            {
                let _state = monitor.state.disable_irq().lock();
                unsafe { monitor.finish_grace_period() };
            }
            monitor.run_completed_callbacks();
            assert_eq!(calls.load(Relaxed), expected);
            // A last-word reporter from the completed period can arrive at
            // the callback lock after the next period has started.
            monitor.run_completed_callbacks();
            assert_eq!(calls.load(Relaxed), expected);
        }
        // Redundant reports must not reacquire the callback lock.
        let _state = monitor.state.disable_irq().lock();
        unsafe { monitor.finish_grace_period() };
    }
}
