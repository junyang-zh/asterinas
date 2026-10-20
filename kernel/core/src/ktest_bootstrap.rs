// SPDX-License-Identifier: MPL-2.0

//! Starts core ktests as real kernel threads on the affinity-aware scheduler.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ostd::{
    cpu::{CpuId, PinCurrentCpu, all_cpus, num_cpus},
    power::{ExitCode, poweroff},
    task::{Task, disable_preempt},
    util::id_set::Id,
};

use crate::{sched::SchedPolicy, thread::kernel_thread::ThreadOptions};

static READY_CPUS: AtomicUsize = AtomicUsize::new(0);
const BOOTSTRAP_TIMEOUT_SECONDS: u64 = 10;

#[ostd::ktest::bootstrap]
fn bootstrap(run_tests: fn()) {
    // Install the real scheduler before a raw OSTD task can select lazy FIFO.
    // Keep BSP bootstrap nonpreemptible until both its tasks are enqueued.
    let guard = disable_preempt();
    require(guard.current_cpu() == CpuId::bsp(), "bootstrap is not on BSP");
    require(Task::current().is_none(), "bootstrap already has a task");
    crate::time::clocks::init_for_ktest();
    crate::thread::init();
    crate::sched::init();
    init_on_cpu();
    ostd::boot::smp::register_ap_entry(init_on_cpu);

    ThreadOptions::new(move || {
        verify_affinity(CpuId::bsp());
        READY_CPUS.fetch_add(1, Ordering::Release);
        wait_until(
            || READY_CPUS.load(Ordering::Acquire) == num_cpus(),
            "not all CPUs reached their kernel-thread context",
        );

        // Exercise the same affinity path as the tests, from a task context.
        // The BSP probe needs yield_now while its controller waits on BSP.
        for cpu in all_cpus() {
            let finished = Arc::new(AtomicBool::new(false));
            let worker_finished = finished.clone();
            let worker = ThreadOptions::new(move || {
                verify_affinity(cpu);
                ostd::early_println!("KTEST_BOOTSTRAP_AFFINITY cpu={}", cpu.as_usize());
                worker_finished.store(true, Ordering::Release);
            })
            .cpu_affinity(cpu.into())
            .spawn();
            wait_until(
                || finished.load(Ordering::Acquire),
                "an affinity probe did not run",
            );
            worker.join();
        }
        ostd::early_println!("KTEST_BOOTSTRAP_READY cpus={}", num_cpus());
        // The existing runner retains named-test panic capture, counts, and
        // success/failure poweroff. Its callback never normally returns.
        run_tests();
        fail("test runner unexpectedly returned");
    })
    .cpu_affinity(CpuId::bsp().into())
    .spawn();
    drop(guard);
}

fn init_on_cpu() {
    // APs arrive here through their ordinary late boot entry, not an IPI.
    let guard = disable_preempt();
    let cpu = guard.current_cpu();
    crate::sched::init_on_each_cpu();
    ThreadOptions::new(move || {
        verify_affinity(cpu);
        if cpu != CpuId::bsp() {
            READY_CPUS.fetch_add(1, Ordering::Release);
        }
        loop {
            Task::yield_now();
            core::hint::spin_loop();
        }
    })
    .cpu_affinity(cpu.into())
    .sched_policy(SchedPolicy::Idle)
    .spawn();
    drop(guard);
}

fn verify_affinity(expected: CpuId) {
    let guard = disable_preempt();
    require(guard.current_cpu() == expected, "task ran on the wrong CPU");
    let Some(thread) = crate::thread::Thread::current() else {
        fail("task has no kernel Thread");
    };
    let affinity = thread.atomic_cpu_affinity().load(Ordering::Acquire);
    require(
        affinity.contains(expected) && affinity.iter().count() == 1,
        "task affinity is not the requested singleton",
    );
}

fn wait_until(mut complete: impl FnMut() -> bool, message: &str) {
    let start = ostd::arch::read_tsc();
    let frequency = ostd::arch::tsc_freq();
    require(frequency != 0, "TSC frequency is zero");
    let budget = frequency.saturating_mul(BOOTSTRAP_TIMEOUT_SECONDS);
    while !complete() {
        if ostd::arch::read_tsc().wrapping_sub(start) >= budget {
            fail(message);
        }
        Task::yield_now();
        core::hint::spin_loop();
    }
}

fn require(condition: bool, message: &str) {
    if !condition {
        fail(message);
    }
}

fn fail(message: &str) -> ! {
    // Setup failures must never be mistaken for an expected red assertion.
    ostd::early_println!("KTEST_BOOTSTRAP_FAILED: {}", message);
    poweroff(ExitCode::Failure);
}
