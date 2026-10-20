// SPDX-License-Identifier: MPL-2.0

//! Optional bounded event recorder for offline exclusive CPU accounting.
//!
//! Hot paths allocate nothing and take only the current CPU's IRQ-safe lock.
//! Control operations run in task context; no I/O occurs under recorder locks.
//! Monotonic task identities prevent reuse within an epoch. Overflow
//! and incomplete initial state are exported, never repaired with residuals.

use alloc::{string::String, vec::Vec};

mod aggregate;
use aggregate::{CpuState, TASK_SLOTS, TaskState};
use core::{
    fmt::Write,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use spin::Once;

use crate::{
    cpu::{CpuSet, PinCurrentCpu, num_cpus},
    irq,
    sync::SpinLock,
    task::Task,
    util::id_set::Id,
};

/// Semantic phases shared with the userspace v1 accounting schema.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Phase {
    /// User execution region, excluding separately hooked IRQs and scheduling.
    User,
    /// mmap syscall, including its validation and cleanup.
    Mmap,
    /// VMAR page-fault handling, including kernel copies into user memory.
    PageFault,
    /// munmap syscall.
    Munmap,
    /// madvise syscall.
    Madvise,
    /// mprotect syscall.
    Mprotect,
    /// Scheduler decision and context switching.
    Scheduler,
    /// CPU-local IRQ top and bottom halves.
    Interrupt,
    /// Kernel work outside more specific phases.
    OtherKernel,
    /// State not observed or classified.
    Unknown,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Mmap => "mmap",
            Self::PageFault => "page_fault",
            Self::Munmap => "munmap",
            Self::Madvise => "madvise",
            Self::Mprotect => "mprotect",
            Self::Scheduler => "scheduler",
            Self::Interrupt => "interrupt",
            Self::OtherKernel => "other_kernel",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy)]
struct Event {
    ts: u64,
    tid: u64,
    other: u64,
    kind: &'static str,
    phase: Phase,
    error: bool,
}

struct Buffer {
    events: Vec<Event>,
    lost: u64,
    initial: Option<(u64, u64, u8)>,
    aggregate: CpuState,
}

// Bounded diagnostic mode, intentionally separate from performance runs.
static ONLINE: AtomicBool = AtomicBool::new(false);
static TASKS: Once<Vec<SpinLock<TaskState>>> = Once::new();
static EVENTS_PER_CPU: AtomicUsize = AtomicUsize::new(8192);
static BUFFERS: Once<Vec<SpinLock<Buffer>>> = Once::new();
static CLOCK: Once<fn() -> u64> = Once::new();
static ACTIVE: AtomicU64 = AtomicU64::new(0);
static EPOCH: AtomicU64 = AtomicU64::new(0);
static CONTROL_BUSY: AtomicBool = AtomicBool::new(false);
static BEGIN: AtomicU64 = AtomicU64::new(0);
static END: AtomicU64 = AtomicU64::new(0);
static ROOT: AtomicU64 = AtomicU64::new(0);
static START_READY: AtomicBool = AtomicBool::new(false);

/// Stable task identity; zero identifies a permanently idle thread.
pub fn task_id(task: &Task) -> u64 {
    if task.profile_is_idle.load(Ordering::Relaxed) {
        0
    } else {
        task.profile_id
    }
}

/// Identifies the current task as a permanently idle thread. Call during boot.
pub fn mark_idle() {
    if let Some(task) = Task::current() {
        task.profile_is_idle.store(true, Ordering::Relaxed);
    }
}

/// Returns the current task's epoch-local identity, or zero in idle/bootstrap context.
pub fn current_task_id() -> u64 {
    Task::current().map_or(0, |task| task_id(&task))
}

fn emit(epoch: u64, kind: &'static str, tid: u64, other: u64, phase: Phase, error: bool) {
    if epoch == 0 || ACTIVE.load(Ordering::Relaxed) != epoch {
        return;
    }
    let irq = irq::disable_local();
    let buffers = BUFFERS.get().unwrap();
    let mut buffer = buffers[irq.current_cpu().as_usize()].disable_irq().lock();
    // Stop/reset cannot race this second check and record append.
    if ACTIVE.load(Ordering::Acquire) != epoch {
        return;
    }
    let ts = (CLOCK.get().unwrap())();
    if buffer.initial.is_none() {
        buffer.initial = Some((
            ts,
            current_task_id(),
            irq::InterruptLevel::current().as_u8(),
        ));
    }
    if ONLINE.load(Ordering::Relaxed) {
        aggregate_event(
            &mut buffer,
            irq.current_cpu().as_usize(),
            ts,
            kind,
            tid,
            other,
            phase,
            error,
        );
        return;
    }
    if buffer.events.len() == buffer.events.capacity() {
        buffer.lost = buffer.lost.saturating_add(1);
        return;
    }
    buffer.events.push(Event {
        ts,
        tid,
        other,
        kind,
        phase,
        error,
    });
}

fn event(kind: &'static str, tid: u64, other: u64, phase: Phase) {
    emit(
        ACTIVE.load(Ordering::Relaxed),
        kind,
        tid,
        other,
        phase,
        false,
    );
}

/// Phase guard retains task identity through sleep and migration. It never pins a CPU.
#[must_use]
pub struct Guard {
    epoch: u64,
    tid: u64,
    phase: Phase,
    error: bool,
}
impl Guard {
    /// Marks an unsuccessful operation; drop still emits its balanced exit.
    pub fn fail(&mut self) {
        self.error = true;
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        emit(self.epoch, "exit", self.tid, 0, self.phase, self.error);
    }
}
/// Enters a nested semantic operation.
pub fn enter(phase: Phase) -> Guard {
    let epoch = ACTIVE.load(Ordering::Relaxed);
    let tid = if epoch == 0 { 0 } else { current_task_id() };
    // Idle threads have no scoped task stack; their scheduling intervals stay
    // in guest idle capacity. Never emit a task event for the idle sentinel.
    let epoch = if tid == 0 { 0 } else { epoch };
    emit(epoch, "enter", tid, 0, phase, false);
    Guard {
        epoch,
        tid,
        phase,
        error: false,
    }
}
/// Records a user/kernel execution boundary.
pub fn mode(phase: Phase) {
    if ACTIVE.load(Ordering::Relaxed) != 0 {
        event("mode", current_task_id(), 0, phase);
    }
}
/// Records the actual processor context switch; zero is idle.
pub fn switch(prev: u64, next: u64) {
    if prev != next {
        event("switch", prev, next, Phase::Unknown);
    }
}
/// Records task-tree membership before the child is first scheduled.
pub fn fork(parent: u64, child: u64) {
    event("fork", parent, child, Phase::OtherKernel);
}
/// Records final task termination (before its identity may be reused).
pub fn exit_task(tid: u64) {
    event("task_exit", tid, 0, Phase::OtherKernel);
}
/// Begins CPU-local interrupt processing, including its bottom half.
pub fn irq_enter() {
    event("irq_enter", 0, 0, Phase::Interrupt);
}
/// Ends CPU-local interrupt processing.
pub fn irq_exit() {
    event("irq_exit", 0, 0, Phase::Interrupt);
}

struct ControlGuard;
impl Drop for ControlGuard {
    fn drop(&mut self) {
        CONTROL_BUSY.store(false, Ordering::Release);
    }
}
fn control() -> Result<ControlGuard, &'static str> {
    CONTROL_BUSY
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| "collector control busy")?;
    Ok(ControlGuard)
}

/// Starts a new epoch. Clock must return monotonic nanoseconds on every CPU.
/// Callers must hold the administrative capability and serialize whole experiments.
pub fn start(clock: fn() -> u64, capacity: usize) -> Result<(), &'static str> {
    start_mode(clock, capacity, false)
}

/// Starts bounded online accounting; task-slot exhaustion invalidates the snapshot.
pub fn start_online(clock: fn() -> u64) -> Result<(), &'static str> {
    start_mode(clock, 64, true)
}

fn start_mode(clock: fn() -> u64, capacity: usize, online: bool) -> Result<(), &'static str> {
    let _control = control()?;
    if ACTIVE.load(Ordering::Acquire) != 0 {
        return Err("collector already active");
    }
    if !(64..=1_048_576).contains(&capacity) {
        return Err("event capacity must be 64..1048576 per CPU");
    }
    CLOCK.call_once(|| clock);
    let buffers = BUFFERS.call_once(|| {
        (0..num_cpus())
            .map(|_| {
                SpinLock::new(Buffer {
                    events: Vec::new(),
                    lost: 0,
                    initial: None,
                    aggregate: CpuState::new(),
                })
            })
            .collect()
    });
    ONLINE.store(online, Ordering::Relaxed);
    if online {
        let tasks = TASKS.call_once(|| {
            (0..TASK_SLOTS)
                .map(|_| SpinLock::new(TaskState::new(0)))
                .collect()
        });
        for task in tasks {
            *task.disable_irq().lock() = TaskState::new(0);
        }
        let tid = current_task_id();
        let mut root = tasks[tid as usize % TASK_SLOTS].disable_irq().lock();
        *root = TaskState::new(tid);
        root.scoped = true;
    }
    for buffer in buffers {
        // Allocation and freeing happen with IRQs enabled, before the epoch.
        let fresh = Vec::with_capacity(capacity);
        let old = {
            let mut buffer = buffer.disable_irq().lock();
            buffer.lost = 0;
            buffer.initial = None;
            buffer.aggregate = CpuState::new();
            core::mem::replace(&mut buffer.events, fresh)
        };
        drop(old);
    }
    EVENTS_PER_CPU.store(capacity, Ordering::Relaxed);
    let epoch = EPOCH
        .load(Ordering::Relaxed)
        .checked_add(1)
        .ok_or("epoch overflow")?;
    EPOCH.store(epoch, Ordering::Relaxed);
    ROOT.store(current_task_id(), Ordering::Relaxed);
    BEGIN.store(if online { 0 } else { clock() }, Ordering::Relaxed);
    END.store(0, Ordering::Relaxed);
    START_READY.store(false, Ordering::Relaxed);
    ACTIVE.store(epoch, Ordering::Release);
    // Establish every CPU's initial state before the caller can launch its
    // command. This avoids clipping most of a short workload while waiting for
    // an otherwise idle CPU's first timer interrupt. The IPI callbacks allocate
    // nothing. No recorder lock is held across IPI dispatch or polling.
    crate::smp::inter_processor_call(&CpuSet::new_full(), || {
        event("marker", current_task_id(), 0, Phase::Unknown);
    });
    let deadline = clock().saturating_add(1_000_000_000);
    loop {
        let ready = buffers.iter().all(|buffer| {
            buffer
                .disable_irq()
                .try_lock()
                .is_some_and(|buffer| buffer.initial.is_some())
        });
        if ready {
            START_READY.store(true, Ordering::Release);
            break;
        }
        if clock() >= deadline {
            // Keep the raw failed epoch exportable. Consumers reject this
            // attestation instead of treating missing CPU state as idle time.
            break;
        }
        core::hint::spin_loop();
    }
    if online {
        // Lock order: CPU buffers ascending, then at most one task slot. Event
        // paths hold one CPU buffer and at most one task slot; no reverse edge.
        // Reserve before disabling IRQs. Never send/wait for IPIs under locks.
        let mut guards = Vec::with_capacity(buffers.len());
        for buffer in buffers {
            guards.push(buffer.disable_irq().lock());
        }
        let begin = clock();
        BEGIN.store(begin, Ordering::Release);
        for buffer in &mut guards {
            buffer.aggregate.last = begin;
        }
    }
    Ok(())
}

/// Stops and drains all per-CPU record writers at a recorded common boundary.
/// Each buffer lock acknowledges every in-flight append without an IPI wait.
pub fn stop() -> Result<(), &'static str> {
    let _control = control()?;
    let clock = CLOCK.get().ok_or("collector has not run")?;
    if ONLINE.load(Ordering::Relaxed) {
        let buffers = BUFFERS.get().unwrap();
        let mut guards = Vec::with_capacity(buffers.len());
        for buffer in buffers {
            guards.push(buffer.disable_irq().lock());
        }
        if ACTIVE.swap(0, Ordering::AcqRel) == 0 {
            return Err("collector not active");
        }
        let end = clock();
        for buffer in &mut guards {
            aggregate_charge(&mut buffer.aggregate, end);
        }
        END.store(end, Ordering::Release);
        return Ok(());
    }
    let end = clock();
    if ACTIVE.swap(0, Ordering::AcqRel) == 0 {
        return Err("collector not active");
    }
    for buffer in BUFFERS.get().unwrap() {
        drop(buffer.disable_irq().lock());
    }
    END.store(end, Ordering::Release);
    Ok(())
}

/// Produces a stable stopped snapshot as JSONL, including every dropped-record count.
/// Snapshot cloning occurs after stop; formatting never holds a recorder lock.
pub fn snapshot() -> Result<String, &'static str> {
    let _control = control()?;
    if ACTIVE.load(Ordering::Acquire) != 0 {
        return Err("stop before snapshot");
    }
    let buffers = BUFFERS.get().ok_or("collector has not run")?;
    if ONLINE.load(Ordering::Relaxed) {
        return aggregate_snapshot(buffers);
    }
    let mut output = String::new();
    // Consumers replay the captured prefix and use a common observed interval.
    // The rendezvous ensures command launch follows every CPU's initial state;
    // its bounded timeout is explicit and invalidates the window.
    writeln!(output, "{{\"type\":\"header\",\"schema_version\":1,\"epoch\":{},\"begin_ns\":{},\"end_ns\":{},\"root_tid\":{},\"cpu_count\":{},\"complete_hooks\":true,\"start_rendezvous_complete\":{},\"clock\":\"aster_time_monotonic_ns\",\"events_per_cpu\":{}}}",
        EPOCH.load(Ordering::Relaxed), BEGIN.load(Ordering::Relaxed), END.load(Ordering::Relaxed),
        ROOT.load(Ordering::Relaxed), buffers.len(), START_READY.load(Ordering::Acquire), EVENTS_PER_CPU.load(Ordering::Relaxed)).unwrap();
    for (cpu, buffer) in buffers.iter().enumerate() {
        let (events, lost, initial) = {
            let buffer = buffer.disable_irq().lock();
            (buffer.events.clone(), buffer.lost, buffer.initial)
        };
        if let Some((ts, tid, irq_depth)) = initial {
            writeln!(
                output,
                "{{\"type\":\"cpu_start\",\"cpu\":{},\"ts_ns\":{},\"tid\":{},\"irq_depth\":{}}}",
                cpu, ts, tid, irq_depth
            )
            .unwrap();
        }
        for (seq, e) in events.iter().enumerate() {
            writeln!(output, "{{\"type\":\"event\",\"ts_ns\":{},\"cpu\":{},\"seq\":{},\"event\":\"{}\",\"tid\":{},\"other_tid\":{},\"phase\":\"{}\",\"error\":{}}}",
                e.ts, cpu, seq, e.kind, e.tid, e.other, e.phase.name(), e.error).unwrap();
        }
        writeln!(
            output,
            "{{\"type\":\"cpu_end\",\"cpu\":{},\"events\":{},\"lost\":{}}}",
            cpu,
            events.len(),
            lost
        )
        .unwrap();
    }
    Ok(output)
}

// Task slots are never reused within an epoch: collisions fail explicitly. This
// bounds memory independently of event rate and avoids stale guard attribution.
fn with_task<R>(tid: u64, f: impl FnOnce(&mut TaskState) -> R) -> Option<R> {
    if tid == 0 {
        return None;
    }
    let mut task = TASKS.get().unwrap()[tid as usize % TASK_SLOTS]
        .disable_irq()
        .lock();
    if task.tid == 0 {
        *task = TaskState::new(tid);
    }
    if task.tid != tid {
        return None;
    }
    Some(f(&mut task))
}

fn aggregate_charge(cpu: &mut CpuState, ts: u64) {
    let begin = BEGIN.load(Ordering::Relaxed);
    if cpu.tid == 0 {
        cpu.charge(None, ts, begin);
    } else if with_task(cpu.tid, |task| cpu.charge(Some(task), ts, begin)).is_none() {
        cpu.invalid += 1;
        cpu.charge(None, ts, begin);
    }
}

fn aggregate_event(
    buffer: &mut Buffer,
    cpu_id: usize,
    ts: u64,
    kind: &str,
    tid: u64,
    other: u64,
    phase: Phase,
    error: bool,
) {
    let cpu = &mut buffer.aggregate;
    if cpu.events == 0 {
        let (_, initial_tid, irq_depth) = buffer.initial.unwrap();
        cpu.tid = initial_tid;
        cpu.irq = irq_depth;
        cpu.last = ts;
        with_task(initial_tid, |task| task.running = Some(cpu_id));
    }
    aggregate_charge(cpu, ts);
    cpu.events += 1;
    let begin = BEGIN.load(Ordering::Relaxed);
    match kind {
        "irq_enter" => {
            if let Some(depth) = cpu.irq.checked_add(1) {
                cpu.irq = depth;
            } else {
                cpu.invalid += 1;
            }
        }
        "irq_exit" => {
            if cpu.irq == 0 {
                cpu.invalid += 1;
            } else {
                cpu.irq -= 1;
            }
        }
        "switch" => {
            if cpu.tid != tid || cpu.irq != 0 {
                cpu.invalid += 1;
            }
            with_task(tid, |task| {
                task.running = None;
                task.off_start = Some(ts);
            });
            if other != 0 && with_task(other, |task| task.resume(cpu_id, ts, begin)) != Some(true) {
                cpu.invalid += 1;
            }
            cpu.tid = other;
        }
        "fork" => {
            let scoped = with_task(tid, |task| task.scoped).unwrap_or(false);
            if with_task(other, |task| {
                task.scoped = scoped;
                task.off_start = Some(ts);
            })
            .is_none()
            {
                cpu.invalid += 1;
            }
        }
        "enter" | "exit" | "mode" | "task_exit" => {
            if cpu.tid != tid {
                cpu.invalid += 1;
            }
            if with_task(tid, |task| match kind {
                "enter" => {
                    if !task.enter(phase) {
                        cpu.invalid += 1;
                    }
                    if task.scoped && begin != 0 {
                        cpu.entries[phase as usize] += 1;
                    }
                }
                "exit" => {
                    if !task.exit(phase) {
                        cpu.invalid += 1;
                    }
                    if task.scoped && error && begin != 0 {
                        cpu.failures[phase as usize] += 1;
                    }
                }
                "mode" => task.base = phase,
                _ => {
                    if task.depth != 0 {
                        cpu.invalid += 1;
                    }
                    task.alive = false;
                    task.off_start = None;
                }
            })
            .is_none()
            {
                cpu.invalid += 1;
            }
        }
        _ => {}
    }
}

fn aggregate_snapshot(buffers: &[SpinLock<Buffer>]) -> Result<String, &'static str> {
    let begin = BEGIN.load(Ordering::Acquire);
    let end = END.load(Ordering::Acquire);
    let mut output = String::new();
    writeln!(output, "{{\"type\":\"aggregate_header\",\"schema_version\":1,\"epoch\":{},\"begin_ns\":{},\"end_ns\":{},\"root_tid\":{},\"cpu_count\":{},\"complete_hooks\":true,\"start_rendezvous_complete\":{},\"clock\":\"aster_time_monotonic_ns\",\"task_slots\":{}}}",
        EPOCH.load(Ordering::Relaxed), begin, end, ROOT.load(Ordering::Relaxed), buffers.len(), START_READY.load(Ordering::Acquire), TASK_SLOTS).unwrap();
    for (id, buffer) in buffers.iter().enumerate() {
        let cpu = buffer.disable_irq().lock().aggregate.clone();
        writeln!(output, "{{\"type\":\"aggregate_cpu\",\"cpu\":{},\"exclusive\":{:?},\"inclusive\":{:?},\"entries\":{:?},\"failures\":{:?},\"idle_ns\":{},\"unrelated_ns\":{},\"unscoped_irq_ns\":{},\"invalid\":{},\"events\":{}}}", id, cpu.exclusive, cpu.inclusive, cpu.entries, cpu.failures, cpu.idle, cpu.unrelated, cpu.unscoped_irq, cpu.invalid, cpu.events).unwrap();
    }
    let mut tasks = 0;
    let mut off_ns = 0;
    let mut open_stacks = 0;
    for task in TASKS.get().unwrap() {
        let task = task.disable_irq().lock();
        if !task.scoped {
            continue;
        }
        tasks += 1;
        off_ns += task.off_ns;
        if task.alive {
            if let Some(start) = task.off_start {
                off_ns += end.saturating_sub(start.max(begin));
            }
        }
        open_stacks += task.depth;
    }
    writeln!(output, "{{\"type\":\"aggregate_tasks\",\"scoped_tasks\":{},\"offcpu_ns\":{},\"open_stack_entries\":{}}}", tasks, off_ns, open_stacks).unwrap();
    Ok(output)
}
