// SPDX-License-Identifier: MPL-2.0

//! Inter-processor interrupts.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{cpu::PinCurrentCpu, irq::IrqLine};

/// Hardware-specific, architecture-dependent CPU ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HwCpuId(u32);

impl HwCpuId {
    #[expect(unused_variables)]
    pub(crate) fn read_current(guard: &dyn PinCurrentCpu) -> Self {
        Self(crate::arch::boot::smp::get_current_hart_id())
    }
}

const IPI_IRQ_NUM_UNINIT: usize = usize::MAX;
static IPI_IRQ_NUM: AtomicUsize = AtomicUsize::new(IPI_IRQ_NUM_UNINIT);

pub(crate) struct IpiGlobalData {
    irq: IrqLine,
}

impl IpiGlobalData {
    pub(crate) fn init() -> Self {
        let mut irq = IrqLine::alloc().unwrap();
        IPI_IRQ_NUM.store(irq.num() as usize, Ordering::Relaxed);
        // SAFETY: This will be called upon an inter-processor interrupt.
        irq.on_active(|f| unsafe { crate::smp::do_inter_processor_call(f) });
        Self { irq }
    }

    /// Sends a general inter-processor interrupt (IPI) to the specified CPU.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the interrupt number is valid and that
    /// the corresponding handler is configured correctly on the remote CPU.
    /// Furthermore, invoking the interrupt handler must also be safe.
    #[expect(unused_variables)]
    pub(crate) unsafe fn send_ipi(&self, hw_cpu_id: HwCpuId, guard: &dyn PinCurrentCpu) {
        const XLEN: usize = core::mem::size_of::<usize>() * 8;
        const XLEN_MASK: usize = XLEN - 1;

        let hart_id = hw_cpu_id.0 as usize;
        let hart_mask_base = hart_id & !XLEN_MASK;
        let hart_mask = 1 << (hart_id & XLEN_MASK);

        let ret = sbi_rt::send_ipi(sbi_rt::HartMask::from_mask_base(hart_mask, hart_mask_base));

        if ret.error == 0 {
            log::debug!("Successfully sent IPI to hart {}", hw_cpu_id.0);
        } else {
            log::error!(
                "Failed to send IPI to hart {}: error code {}",
                hw_cpu_id.0,
                ret.error
            );
        }
    }
}

pub(in crate::arch) fn get_ipi_irq_num() -> usize {
    let n = IPI_IRQ_NUM.load(Ordering::Relaxed);
    assert!(n != IPI_IRQ_NUM_UNINIT);
    n
}
