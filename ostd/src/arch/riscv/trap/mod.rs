// SPDX-License-Identifier: MPL-2.0

//! Handles trap.

#[expect(clippy::module_inception)]
mod trap;

use core::sync::atomic::Ordering;

use spin::Once;
pub(super) use trap::RawUserContext;
pub use trap::TrapFrame;

use super::{
    cpu::context::CpuException,
    irq::{disable_local, enable_local, get_ipi_irq_num},
    timer::TIMER_IRQ_NUM,
};
use crate::{cpu_local_cell, mm::MAX_USERSPACE_VADDR, trap::call_irq_callback_functions};

cpu_local_cell! {
    static IS_KERNEL_INTERRUPTED: bool = false;
}

/// Initializes interrupt handling on RISC-V.
pub(crate) unsafe fn init() {
    unsafe {
        self::trap::init();
    }
}

/// Returns true if this function is called within the context of an IRQ handler
/// and the IRQ occurs while the CPU is executing in the kernel mode.
/// Otherwise, it returns false.
pub fn is_kernel_interrupted() -> bool {
    IS_KERNEL_INTERRUPTED.load()
}

/// Handle traps (only from kernel).
#[no_mangle]
extern "C" fn trap_handler(f: &mut TrapFrame) {
    fn enable_local_if(cond: bool) {
        if cond {
            enable_local();
        }
    }

    fn disable_local_if(cond: bool) {
        if cond {
            disable_local();
        }
    }

    use riscv::interrupt::{
        supervisor::{Exception, Interrupt},
        Trap,
    };

    let scause = riscv::interrupt::supervisor::cause::<Interrupt, Exception>();
    match scause {
        Trap::Interrupt(interrupt) => {
            IS_KERNEL_INTERRUPTED.store(true);
            match interrupt {
                Interrupt::SupervisorTimer => {
                    call_irq_callback_functions(f, TIMER_IRQ_NUM.load(Ordering::Relaxed) as usize);
                }
                Interrupt::SupervisorExternal => {
                    super::irq::handle_supervisor_external_interrupt(f);
                }
                Interrupt::SupervisorSoft => {
                    call_irq_callback_functions(f, get_ipi_irq_num());
                }
            }
            IS_KERNEL_INTERRUPTED.store(false);
        }
        Trap::Exception(e) => {
            use CpuException::*;

            let exception = e.into();
            // The IRQ state before trapping. We need to ensure that the IRQ state
            // during exception handling is consistent with the state before the trap.
            let was_irq_enabled = riscv::register::sstatus::read().spie();
            enable_local_if(was_irq_enabled);
            match exception {
                InstructionPageFault(fault_addr)
                | LoadPageFault(fault_addr)
                | StorePageFault(fault_addr) => {
                    if (0..MAX_USERSPACE_VADDR).contains(&fault_addr.0) {
                        handle_user_page_fault(f, &exception);
                    }
                }
                _ => {
                    panic!(
                        "Cannot handle kernel exception, exception: {:?}, trapframe: {:#x?}.",
                        exception, f
                    );
                }
            };
            disable_local_if(was_irq_enabled);
        }
    }
}

#[expect(clippy::type_complexity)]
static USER_PAGE_FAULT_HANDLER: Once<fn(&CpuException) -> core::result::Result<(), ()>> =
    Once::new();

/// Injects a custom handler for page faults that occur in the kernel and
/// are caused by user-space address.
pub fn inject_user_page_fault_handler(
    handler: fn(info: &CpuException) -> core::result::Result<(), ()>,
) {
    USER_PAGE_FAULT_HANDLER.call_once(|| handler);
}

fn handle_user_page_fault(f: &mut TrapFrame, exception: &CpuException) {
    let handler = USER_PAGE_FAULT_HANDLER
        .get()
        .expect("Page fault handler is missing");

    handler(exception).unwrap_or_else(|_| {
        panic!(
            "Failed to handle page fault, exception: {:?}, trapframe: {:#x?}.",
            exception, f
        )
    });
}
