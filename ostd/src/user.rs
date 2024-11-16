// SPDX-License-Identifier: MPL-2.0

//! User space.

use crate::{cpu::UserContext, mm::vm_space::SharedVmSpace, trap::TrapFrame};

/// Code execution in the user mode.
///
/// This type enables executing the code in user space from a task in the kernel
/// space safely.
#[derive(Debug)]
pub struct UserMode {
    /// The user VM address space.
    vm_space: SharedVmSpace,
    /// CPU context of the user mode.
    ctx: UserContext,
}

// An instance of `UserMode` is bound to the current task. So it must not be sent to other tasks.
impl !Send for UserMode {}
// Note that implementing `!Sync` is unnecessary
// because entering the user space via `UserMode` requires taking a mutable reference.

impl UserMode {
    /// Creates a new [`UserMode`] instance.
    ///
    /// Each instance maintains a virtual memory address space and the CPU
    /// state to enable execution in the user space.
    pub fn new(vm_space: SharedVmSpace, ctx: UserContext) -> Self {
        Self { vm_space, ctx }
    }

    /// Returns an immutable reference the user-mode CPU context.
    pub fn context(&self) -> &UserContext {
        &self.ctx
    }

    /// Returns a mutable reference the user-mode CPU context.
    pub fn context_mut(&mut self) -> &mut UserContext {
        &mut self.ctx
    }

    /// Gets the virtual memory address space.
    pub fn vm_space(&self) -> &SharedVmSpace {
        &self.vm_space
    }

    /// Gets the virtual memory address space mutably.
    pub fn vm_space_mut(&mut self) -> &mut SharedVmSpace {
        &mut self.vm_space
    }
}

/// A reason as to why the control of the CPU is returned from
/// the user space to the kernel.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ReturnReason {
    /// A system call is issued by the user space.
    UserSyscall,
    /// A CPU exception is triggered by the user space.
    UserException,
    /// A kernel event is pending
    KernelEvent,
}

/// Specific architectures need to implement this trait. This should only used in [`UserMode`]
///
/// Only visible in `ostd`.
pub(crate) trait UserContextApiInternal {
    /// Starts executing in the user mode.
    fn execute<F>(&mut self, has_kernel_event: F) -> ReturnReason
    where
        F: FnMut() -> bool;

    /// Uses the information inside CpuContext to build a trapframe
    fn as_trap_frame(&self) -> TrapFrame;
}

/// The common interface that every CPU architecture-specific [`UserContext`] implements.
pub trait UserContextApi {
    /// Gets the trap number of this interrupt.
    fn trap_number(&self) -> usize;

    /// Gets the trap error code of this interrupt.
    fn trap_error_code(&self) -> usize;

    /// Sets the instruction pointer
    fn set_instruction_pointer(&mut self, ip: usize);

    /// Gets the instruction pointer
    fn instruction_pointer(&self) -> usize;

    /// Sets the stack pointer
    fn set_stack_pointer(&mut self, sp: usize);

    /// Gets the stack pointer
    fn stack_pointer(&self) -> usize;
}
