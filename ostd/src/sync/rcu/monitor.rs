// SPDX-License-Identifier: MPL-2.0

use alloc::collections::VecDeque;
use core::sync::atomic::{
    AtomicBool, AtomicU64,
    Ordering::{Acquire, Relaxed, Release},
};

use crate::{
    cpu::{AtomicCpuSet, CpuId, CpuSet, PinCurrentCpu, num_cpus},
    prelude::*,
    sync::SpinLock,
    task::disable_preempt,
};

/// A RCU monitor ensures the completion of _grace periods_ by keeping track
/// of each CPU's passing _quiescent states_.
pub(super) struct RcuMonitor {
    is_monitoring: AtomicBool,
    state: SpinLock<State>,
    epoch: AtomicU64,
    observed: Box<[ObservedEpoch]>,
}

impl RcuMonitor {
    /// Creates a new RCU monitor.
    ///
    /// This function is used to initialize a singleton instance of `RcuMonitor`.
    /// The singleton instance is globally accessible via the `RCU_MONITOR`.
    pub(super) fn new() -> Self {
        Self {
            is_monitoring: AtomicBool::new(false),
            state: SpinLock::new(State::new()),
            epoch: AtomicU64::new(0),
            observed: (0..num_cpus())
                .map(|_| ObservedEpoch(AtomicU64::new(0)))
                .collect(),
        }
    }

    pub(super) unsafe fn finish_grace_period(&self) {
        // Fast path
        if !self.is_monitoring.load(Relaxed) {
            return;
        }

        // Pin the CPU until its report is recorded. A stale epoch can only
        // postpone a report: epochs never wrap, and only a report under the
        // state lock updates this CPU's cache. At saturation always report.
        let pin = disable_preempt();
        let cpu = pin.current_cpu();
        let epoch = self.epoch.load(Acquire);
        if self.has_reported(cpu, epoch) {
            return;
        }

        // Check if the current GP is complete after passing the quiescent state
        // on the current CPU. If GP is complete, take the callbacks of the current
        // GP.
        let callbacks = {
            let mut state = self.state.disable_irq().lock();
            if state.current_gp.is_complete() {
                return;
            }

            state.current_gp.finish_grace_period(cpu);
            // Record the actual locked epoch, not the potentially stale value
            // read before acquiring the lock. Do this before restarting a GP.
            self.observed[u32::from(cpu) as usize]
                .0
                .store(self.epoch.load(Relaxed), Relaxed);
            if !state.current_gp.is_complete() {
                return;
            }

            // Now that the current GP is complete, take its callbacks
            let current_callbacks = state.current_gp.take_callbacks();

            // Check if we need to watch for a next GP
            if !state.next_callbacks.is_empty() {
                let callbacks = core::mem::take(&mut state.next_callbacks);
                self.restart(&mut state, callbacks);
            } else {
                self.is_monitoring.store(false, Relaxed);
            }

            current_callbacks
        };

        // Callbacks can reschedule; both the state lock and CPU pin must be
        // released first (including when reporting completed the last GP).
        drop(pin);

        // Invoke the callbacks to notify the completion of GP
        for f in callbacks {
            (f)();
        }
    }

    pub(super) fn after_grace_period<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let mut state = self.state.disable_irq().lock();

        state.next_callbacks.push_back(Box::new(f));

        if !state.current_gp.is_complete() {
            return;
        }

        let callbacks = core::mem::take(&mut state.next_callbacks);
        self.restart(&mut state, callbacks);
        self.is_monitoring.store(true, Relaxed);
    }
    fn has_reported(&self, cpu: CpuId, epoch: u64) -> bool {
        epoch != u64::MAX && self.observed[u32::from(cpu) as usize].0.load(Relaxed) == epoch
    }

    // The state lock serializes all grace-period restarts and epoch updates.
    fn restart(&self, state: &mut State, callbacks: Callbacks) {
        state.current_gp.restart(callbacks);
        self.epoch
            .store(self.epoch.load(Relaxed).saturating_add(1), Release);
    }
}

// Avoid cache-line writes by other CPUs invalidating the local report cache.
#[repr(align(64))]
struct ObservedEpoch(AtomicU64);

struct State {
    current_gp: GracePeriod,
    next_callbacks: Callbacks,
}

impl State {
    fn new() -> Self {
        Self {
            current_gp: GracePeriod::new(),
            next_callbacks: VecDeque::new(),
        }
    }
}

type Callbacks = VecDeque<Box<dyn FnOnce() + Send + 'static>>;

struct GracePeriod {
    callbacks: Callbacks,
    cpu_mask: AtomicCpuSet,
    is_complete: bool,
}

impl GracePeriod {
    fn new() -> Self {
        Self {
            callbacks: Callbacks::new(),
            cpu_mask: AtomicCpuSet::new(CpuSet::new_empty()),
            is_complete: true,
        }
    }

    fn is_complete(&self) -> bool {
        self.is_complete
    }

    fn finish_grace_period(&mut self, this_cpu: CpuId) {
        self.cpu_mask.add(this_cpu, Relaxed);

        if self.cpu_mask.load(Relaxed).is_full() {
            self.is_complete = true;
        }
    }

    fn take_callbacks(&mut self) -> Callbacks {
        core::mem::take(&mut self.callbacks)
    }

    fn restart(&mut self, callbacks: Callbacks) {
        self.is_complete = false;
        self.cpu_mask.store(&CpuSet::new_empty(), Relaxed);
        self.callbacks = callbacks;
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{cpu::all_cpus, task::atomic_mode::might_sleep};

    // These monitors contain only test callbacks, with no protected readers.
    // Completing their synthetic CPU masks cannot reclaim live RCU objects.
    #[ktest]
    fn report_cache_tracks_restarts_and_stale_epochs() {
        let monitor = RcuMonitor::new();
        let pin = disable_preempt();
        let cpu = pin.current_cpu();
        monitor.after_grace_period(|| {});
        let first = monitor.epoch.load(Acquire);
        unsafe { monitor.finish_grace_period() };
        assert!(monitor.has_reported(cpu, first));

        // A redundant report must not acquire the global lock. In particular,
        // busy idle CPUs must not starve interrupt delivery behind this lock.
        {
            let _state = monitor.state.disable_irq().lock();
            unsafe { monitor.finish_grace_period() };
        }

        // Model a restart racing a stale fast-path epoch load. Skipping that
        // stale report is safe, but must not mark this CPU in the new period.
        {
            let mut state = monitor.state.disable_irq().lock();
            monitor.restart(&mut state, Callbacks::new());
            monitor.is_monitoring.store(true, Relaxed);
        }
        let second = monitor.epoch.load(Acquire);
        assert_eq!(second, first + 1);
        assert!(monitor.has_reported(cpu, first));
        assert!(!monitor.has_reported(cpu, second));
        assert!(
            !monitor
                .state
                .disable_irq()
                .lock()
                .current_gp
                .cpu_mask
                .contains(cpu, Relaxed)
        );
        unsafe { monitor.finish_grace_period() };
        assert!(monitor.has_reported(cpu, second));
        assert!(
            monitor
                .state
                .disable_irq()
                .lock()
                .current_gp
                .cpu_mask
                .contains(cpu, Relaxed)
        );
    }

    #[ktest]
    fn saturated_epoch_never_skips_a_report() {
        let monitor = RcuMonitor::new();
        let pin = disable_preempt();
        let cpu = pin.current_cpu();
        monitor.epoch.store(u64::MAX - 1, Relaxed);
        for _ in 0..3 {
            {
                let mut state = monitor.state.disable_irq().lock();
                monitor.restart(&mut state, Callbacks::new());
                monitor.is_monitoring.store(true, Relaxed);
            }
            assert_eq!(monitor.epoch.load(Acquire), u64::MAX);
            assert!(!monitor.has_reported(cpu, u64::MAX));
            unsafe { monitor.finish_grace_period() };
            assert!(
                monitor
                    .state
                    .disable_irq()
                    .lock()
                    .current_gp
                    .cpu_mask
                    .contains(cpu, Relaxed)
            );
        }
    }

    #[ktest]
    fn callbacks_run_without_the_report_pin() {
        let monitor = RcuMonitor::new();
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = called.clone();
        monitor.after_grace_period(move || {
            might_sleep();
            callback_called.store(true, Relaxed);
        });
        {
            let mut state = monitor.state.disable_irq().lock();
            for cpu in all_cpus() {
                state.current_gp.cpu_mask.add(cpu, Relaxed);
            }
        }
        unsafe { monitor.finish_grace_period() };
        assert!(called.load(Relaxed));
    }
}
