// SPDX-License-Identifier: MPL-2.0

use ostd::cpu::context::{CpuException, UserContext};

use crate::process::signal::{
    constants::*, sig_num::SigNum, signals::fault::FaultSignal, SignalContext,
};

impl SignalContext for UserContext {
    fn set_arguments(&mut self, sig_num: SigNum, siginfo_addr: usize, ucontext_addr: usize) {
        self.set_a0(sig_num.as_u8() as usize);
        self.set_a1(siginfo_addr);
        self.set_a2(ucontext_addr);
    }
}

impl From<&CpuException> for FaultSignal {
    fn from(exception: &CpuException) -> Self {
        let (num, code, addr) = match exception {
            // Instruction exceptions
            CpuException::InstructionMisaligned => (SIGBUS, BUS_ADRALN, None),
            CpuException::InstructionFault => (SIGSEGV, SEGV_ACCERR, None),
            CpuException::IllegalInstruction(_) => (SIGILL, ILL_ILLOPC, None),
            CpuException::Breakpoint => (SIGTRAP, 1, None), // TRAP_BRKPT equivalent

            // Load/Store misalignment exceptions
            CpuException::LoadMisaligned(fault_addr) => {
                (SIGBUS, BUS_ADRALN, Some(fault_addr.0 as u64))
            }
            CpuException::StoreMisaligned(fault_addr) => {
                (SIGBUS, BUS_ADRALN, Some(fault_addr.0 as u64))
            }

            // Load/Store access fault exceptions
            CpuException::LoadFault(fault_addr) => (SIGBUS, BUS_ADRERR, Some(fault_addr.0 as u64)),
            CpuException::StoreFault(fault_addr) => (SIGBUS, BUS_ADRERR, Some(fault_addr.0 as u64)),

            // Page fault exceptions
            CpuException::InstructionPageFault(fault_addr) => {
                (SIGSEGV, SEGV_MAPERR, Some(fault_addr.0 as u64))
            }
            CpuException::LoadPageFault(fault_addr) => {
                (SIGSEGV, SEGV_MAPERR, Some(fault_addr.0 as u64))
            }
            CpuException::StorePageFault(fault_addr) => {
                (SIGSEGV, SEGV_MAPERR, Some(fault_addr.0 as u64))
            }

            // Environment calls - these shouldn't normally generate fault signals
            // as they are handled as system calls, but if they do reach here,
            // treat as illegal instruction
            CpuException::UserEnvCall
            | CpuException::SupervisorEnvCall
            | CpuException::MachineEnvCall => (SIGILL, ILL_ILLTRP, None),

            // Unknown exception
            CpuException::Unknown => (SIGILL, ILL_ILLOPC, None),
        };

        FaultSignal::new(num, code, addr)
    }
}
