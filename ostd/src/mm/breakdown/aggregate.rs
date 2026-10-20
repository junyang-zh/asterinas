// SPDX-License-Identifier: MPL-2.0

//! Allocation-free accounting state, independent of kernel locking and clocks.

use super::Phase;

pub(super) const PHASES: usize = 10;
pub(super) const MAX_DEPTH: usize = 64;
pub(super) const TASK_SLOTS: usize = 65_536;

#[derive(Clone)]
pub(super) struct TaskState {
    pub tid: u64,
    pub scoped: bool,
    pub alive: bool,
    pub base: Phase,
    pub stack: [Phase; MAX_DEPTH],
    pub depth: usize,
    pub running: Option<usize>,
    pub off_start: Option<u64>,
    pub off_ns: u64,
}
impl TaskState {
    pub fn new(tid: u64) -> Self {
        Self {
            tid,
            scoped: false,
            alive: true,
            base: Phase::OtherKernel,
            stack: [Phase::Unknown; MAX_DEPTH],
            depth: 0,
            running: None,
            off_start: None,
            off_ns: 0,
        }
    }
    pub fn enter(&mut self, phase: Phase) -> bool {
        if self.depth == MAX_DEPTH {
            return false;
        }
        self.stack[self.depth] = phase;
        self.depth += 1;
        true
    }
    pub fn exit(&mut self, phase: Phase) -> bool {
        if self.depth == 0 || self.stack[self.depth - 1] as u8 != phase as u8 {
            return false;
        }
        self.depth -= 1;
        true
    }
    pub fn resume(&mut self, cpu: usize, now: u64, begin: u64) -> bool {
        if self.running.is_some() {
            return false;
        }
        if let Some(start) = self.off_start.take() {
            if now < start {
                return false;
            }
            if begin != 0 {
                self.off_ns += now.saturating_sub(start.max(begin));
            }
        }
        self.running = Some(cpu);
        true
    }
}

#[derive(Clone)]
pub(super) struct CpuState {
    pub tid: u64,
    pub irq: u8,
    pub last: u64,
    pub exclusive: [u64; PHASES],
    pub inclusive: [u64; PHASES],
    pub entries: [u64; PHASES],
    pub failures: [u64; PHASES],
    pub idle: u64,
    pub unrelated: u64,
    pub unscoped_irq: u64,
    pub invalid: u64,
    pub events: u64,
}
impl CpuState {
    pub fn new() -> Self {
        Self {
            tid: 0,
            irq: 0,
            last: 0,
            exclusive: [0; PHASES],
            inclusive: [0; PHASES],
            entries: [0; PHASES],
            failures: [0; PHASES],
            idle: 0,
            unrelated: 0,
            unscoped_irq: 0,
            invalid: 0,
            events: 0,
        }
    }
    pub fn charge(&mut self, task: Option<&TaskState>, now: u64, begin: u64) {
        if now < self.last {
            self.invalid += 1;
            return;
        }
        let dt = if begin == 0 {
            0
        } else {
            now.saturating_sub(self.last.max(begin))
        };
        self.last = now;
        if self.tid == 0 && self.irq == 0 {
            self.idle += dt;
            return;
        }
        let Some(task) = task.filter(|t| t.scoped) else {
            self.unrelated += dt;
            if self.irq != 0 {
                self.unscoped_irq += dt;
            }
            return;
        };
        let phase = if self.irq != 0 {
            Phase::Interrupt
        } else if task.depth != 0 {
            task.stack[task.depth - 1]
        } else {
            task.base
        };
        self.exclusive[phase as usize] += dt;
        let mut mask = 1u16 << phase as usize;
        for p in &task.stack[..task.depth] {
            mask |= 1u16 << *p as usize;
        }
        for p in 0..PHASES {
            if mask & (1 << p) != 0 {
                self.inclusive[p] += dt;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_fault_irq_and_sleep_do_not_double_charge() {
        let mut task = TaskState::new(7);
        task.scoped = true;
        task.base = Phase::User;
        let mut cpu = CpuState::new();
        cpu.tid = 7;
        cpu.last = 100;
        cpu.charge(Some(&task), 110, 100);
        assert!(task.enter(Phase::Mmap));
        cpu.charge(Some(&task), 120, 100);
        assert!(task.enter(Phase::PageFault));
        cpu.charge(Some(&task), 130, 100);
        cpu.irq = 1;
        cpu.charge(Some(&task), 140, 100);
        cpu.irq = 0;
        assert!(task.exit(Phase::PageFault));
        cpu.charge(Some(&task), 150, 100);
        cpu.tid = 0;
        task.off_start = Some(150);
        cpu.charge(None, 200, 100);
        assert!(task.resume(1, 200, 100));
        assert_eq!(task.off_ns, 50);
        assert_eq!(cpu.exclusive[Phase::User as usize], 10);
        assert_eq!(cpu.exclusive[Phase::Mmap as usize], 20);
        assert_eq!(cpu.exclusive[Phase::PageFault as usize], 10);
        assert_eq!(cpu.exclusive[Phase::Interrupt as usize], 10);
        assert_eq!(cpu.inclusive[Phase::Mmap as usize], 40);
        assert_eq!(cpu.inclusive[Phase::PageFault as usize], 20);
        assert_eq!(cpu.exclusive.iter().sum::<u64>() + cpu.idle, 100);
        assert!(!task.resume(2, 210, 100));
    }
    #[test]
    fn recursion_capacity_unknown_and_clipping_are_explicit() {
        let mut task = TaskState::new(1);
        task.scoped = true;
        for _ in 0..MAX_DEPTH {
            assert!(task.enter(Phase::Mmap));
        }
        assert!(!task.enter(Phase::PageFault));
        assert!(!task.exit(Phase::PageFault));
        let mut cpu = CpuState::new();
        cpu.tid = 1;
        cpu.charge(Some(&task), 120, 100);
        assert_eq!(cpu.inclusive[Phase::Mmap as usize], 20);
        cpu.charge(Some(&task), 110, 100);
        assert_eq!(cpu.invalid, 1);
        cpu.tid = 2;
        cpu.charge(None, 130, 100);
        assert_eq!(cpu.unrelated, 10);
    }
}
