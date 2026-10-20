// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;
use core::time::Duration;

use aster_time::read_monotonic_time;
use ostd::{cpu::PinCurrentCpu, cpu_local, sync::SpinLock, task::disable_preempt, timer::Jiffies};
use paste::paste;
use spin::Once;

use crate::time::{
    self, Clock, SystemTime, system_time::START_TIME_AS_DURATION, timer::TimerManager,
};

/// The Clock that reads the jiffies, and turn the counter into `Duration`.
pub(crate) struct JiffiesClock {
    _private: (),
}

/// `RealTimeClock` represents a clock that provides the current real time.
pub(crate) struct RealTimeClock {
    _private: (),
}

impl RealTimeClock {
    /// Get the singleton of this clock.
    pub(crate) fn get() -> &'static Arc<RealTimeClock> {
        CLOCK_REALTIME_INSTANCE.get().unwrap()
    }

    /// Get the cpu-local system-wide `TimerManager` singleton of this clock.
    pub(crate) fn timer_manager() -> &'static Arc<TimerManager> {
        let preempt_guard = disable_preempt();
        CLOCK_REALTIME_MANAGER
            .get_on_cpu(preempt_guard.current_cpu())
            .get()
            .unwrap()
    }
}

/// `MonotonicClock` represents a clock that measures time in a way that is
/// monotonically increasing since the system was booted.
pub(crate) struct MonotonicClock {
    _private: (),
}

impl MonotonicClock {
    /// Get the singleton of this clock.
    pub(crate) fn get() -> &'static Arc<MonotonicClock> {
        CLOCK_MONOTONIC_INSTANCE.get().unwrap()
    }

    /// Get the cpu-local system-wide `TimerManager` singleton of this clock.
    pub(crate) fn timer_manager() -> &'static Arc<TimerManager> {
        let preempt_guard = disable_preempt();
        CLOCK_MONOTONIC_MANAGER
            .get_on_cpu(preempt_guard.current_cpu())
            .get()
            .unwrap()
    }
}

/// `RealTimeCoarseClock` is a coarse-grained version of a real-time clock.
///
/// This clock will maintain a record to `RealTimeClock`. This record
/// will be updated during each system timer interruption. Reading this clock
/// will directly reads the value of the record instead of calculating the time
/// based on the clocksource. Hence it is faster but less accurate.
///
/// Usually it will not be used to create a timer.
pub(crate) struct RealTimeCoarseClock {
    _private: (),
}

impl RealTimeCoarseClock {
    /// Get the singleton of this clock.
    pub(crate) fn get() -> &'static Arc<RealTimeCoarseClock> {
        CLOCK_REALTIME_COARSE_INSTANCE.get().unwrap()
    }
}

/// `MonotonicCoarseClock` is a coarse-grained version of the monotonic clock.
///
/// This clock is based on [`RealTimeCoarseClock`].
///
/// Usually it will not be used to create a timer.
pub(crate) struct MonotonicCoarseClock {
    _private: (),
}

impl MonotonicCoarseClock {
    /// Get the singleton of this clock.
    pub(crate) fn get() -> &'static Arc<MonotonicCoarseClock> {
        CLOCK_MONOTONIC_COARSE_INSTANCE.get().unwrap()
    }
}

/// `MonotonicRawClock` provides raw monotonic time that is not influenced by
/// NTP corrections.
///
/// Note: Currently we have not implement NTP corrections so we treat this clock
/// as the [`MonotonicClock`].
pub(crate) struct MonotonicRawClock {
    _private: (),
}

impl MonotonicRawClock {
    /// Get the singleton of this clock.
    pub(crate) fn get() -> &'static Arc<MonotonicRawClock> {
        CLOCK_MONOTONIC_RAW_INSTANCE.get().unwrap()
    }
}

/// `BootTimeClock` measures the time elapsed since the system was booted,
/// including time when the system was suspended.
///
/// Note: currently the system will not be suspended so we treat this clock
/// as the [`MonotonicClock`].
pub(crate) struct BootTimeClock {
    _private: (),
}

impl BootTimeClock {
    /// Get the singleton of this clock.
    pub(crate) fn get() -> &'static Arc<BootTimeClock> {
        CLOCK_BOOTTIME_INSTANCE.get().unwrap()
    }

    /// Get the cpu-local system-wide `TimerManager` singleton of this clock.
    pub(crate) fn timer_manager() -> &'static Arc<TimerManager> {
        let preempt_guard = disable_preempt();
        CLOCK_BOOTTIME_MANAGER
            .get_on_cpu(preempt_guard.current_cpu())
            .get()
            .unwrap()
    }
}

impl Clock for JiffiesClock {
    fn read_time(&self) -> Duration {
        Jiffies::elapsed().as_duration()
    }
}

impl Clock for RealTimeClock {
    fn read_time(&self) -> Duration {
        SystemTime::now()
            .duration_since(&SystemTime::UNIX_EPOCH)
            .unwrap()
    }
}

impl Clock for MonotonicClock {
    fn read_time(&self) -> Duration {
        read_monotonic_time()
    }
}

impl Clock for RealTimeCoarseClock {
    fn read_time(&self) -> Duration {
        let guard = disable_preempt();
        let mut cached = COARSE_REALTIME
            .get_on_cpu(guard.current_cpu())
            .get()
            .unwrap()
            .disable_irq()
            .lock();
        let ticks = Jiffies::elapsed();
        if cached.0 != ticks.as_u64() {
            // Derive every CPU cache from the same global tick epoch. This
            // avoids stale AP clocks and backwards time after task migration.
            *cached = (
                ticks.as_u64(),
                *START_TIME_AS_DURATION.get().unwrap() + ticks.as_duration(),
            );
        }
        cached.1
    }
}

impl Clock for MonotonicCoarseClock {
    fn read_time(&self) -> Duration {
        RealTimeCoarseClock::get().read_time() - *START_TIME_AS_DURATION.get().unwrap()
    }
}

impl Clock for MonotonicRawClock {
    fn read_time(&self) -> Duration {
        read_monotonic_time()
    }
}

impl Clock for BootTimeClock {
    fn read_time(&self) -> Duration {
        read_monotonic_time()
    }
}

/// Define the system-wide clocks.
macro_rules! define_system_clocks {
    ($($clock_id:ident => $clock_type:ident,)*) => {
        $(
            paste! {
                pub(crate) static [<$clock_id _INSTANCE>]: Once<Arc<$clock_type>> = Once::new();
            }
        )*

        fn _init_system_wide_clocks() {
            $(
                let clock = Arc::new(
                    $clock_type {
                        _private: (),
                    }
                );
                paste! {
                    [<$clock_id _INSTANCE>].call_once(|| clock.clone());
                }
            )*
        }
    }
}

/// Define the timer managers of some system-wide clocks.
macro_rules! define_timer_managers {
    ($($clock_id:ident,)*) => {
        $(
            paste! {
                cpu_local! {
                    pub(crate) static [<$clock_id _MANAGER>]: Once<Arc<TimerManager>> = Once::new();
                }
            }
        )*

        fn _init_system_wide_timer_managers() {
            $(
                let clock = paste! {[<$clock_id _INSTANCE>].get().unwrap().clone()};
                let timer_manager = TimerManager::new(clock);
                for cpu in ostd::cpu::all_cpus() {
                    paste! {
                        [<$clock_id _MANAGER>].get_on_cpu(cpu).call_once(|| timer_manager.clone());
                    }
                }
                let callback = || {
                    let preempt_guard = ostd::task::disable_preempt();
                    let cpu = preempt_guard.current_cpu();
                    paste! {
                        [<$clock_id _MANAGER>].get_on_cpu(cpu).get().unwrap().process_expired_timers();
                    }
                };
                time::softirq::register_callback(callback);
            )*
        }
    }
}

define_system_clocks! {
    CLOCK_REALTIME          => RealTimeClock,
    CLOCK_REALTIME_COARSE   => RealTimeCoarseClock,
    CLOCK_MONOTONIC         => MonotonicClock,
    CLOCK_MONOTONIC_COARSE  => MonotonicCoarseClock,
    CLOCK_MONOTONIC_RAW     => MonotonicRawClock,
    CLOCK_BOOTTIME          => BootTimeClock,
}

define_timer_managers![CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME,];

/// Init the system-wide clocks.
fn init_system_wide_clocks() {
    _init_system_wide_clocks();
}

/// Init the system-wide cpu-local [`TimerManager`]s.
fn init_system_wide_timer_managers() {
    _init_system_wide_timer_managers();
}

/// The system-wide [`TimerManager`] for the [`JiffiesClock`].
pub(crate) static JIFFIES_TIMER_MANAGER: Once<Arc<TimerManager>> = Once::new();

fn init_jiffies_clock_manager() {
    let jiffies_clock = JiffiesClock { _private: () };
    let jiffies_timer_manager = TimerManager::new(Arc::new(jiffies_clock));
    JIFFIES_TIMER_MANAGER.call_once(|| jiffies_timer_manager);

    let callback = || {
        JIFFIES_TIMER_MANAGER
            .get()
            .unwrap()
            .process_expired_timers();
    };
    time::softirq::register_callback(callback);
}

cpu_local! {
    static COARSE_REALTIME: Once<SpinLock<(u64, Duration)>> = Once::new();
}

fn init_coarse_clock() {
    let ticks = Jiffies::elapsed();
    let real_time = *START_TIME_AS_DURATION.get().unwrap() + ticks.as_duration();
    for cpu in ostd::cpu::all_cpus() {
        COARSE_REALTIME
            .get_on_cpu(cpu)
            .call_once(|| SpinLock::new((ticks.as_u64(), real_time)));
    }
}

pub(super) fn init() {
    init_system_wide_clocks();
    init_system_wide_timer_managers();
    init_jiffies_clock_manager();
    init_coarse_clock();
}

#[cfg(ktest)]
/// Init `CLOCK_REALTIME_MANAGER` for process-related ktests.
///
/// TODO: `ktest` may require a feature that allows the registration of initialization functions
/// to avoid functions like this one.
pub(crate) fn init_for_ktest() {
    START_TIME_AS_DURATION.call_once(|| Duration::ZERO);
    // If `spin::Once` has initialized, this closure will not be executed.
    for cpu in ostd::cpu::all_cpus() {
        CLOCK_REALTIME_MANAGER.get_on_cpu(cpu).call_once(|| {
            let clock = RealTimeClock { _private: () };
            TimerManager::new(Arc::new(clock))
        });
    }
    CLOCK_REALTIME_COARSE_INSTANCE.call_once(|| Arc::new(RealTimeCoarseClock { _private: () }));
    for cpu in ostd::cpu::all_cpus() {
        COARSE_REALTIME
            .get_on_cpu(cpu)
            .call_once(|| SpinLock::new((0, Duration::ZERO)));
    }
    JIFFIES_TIMER_MANAGER.call_once(|| {
        let clock = JiffiesClock { _private: () };
        TimerManager::new(Arc::new(clock))
    });
}
