// SPDX-License-Identifier: MPL-2.0

//! Inter-processor interrupts.

use spin::Once;

use crate::{
    arch::kernel::apic::{self, ApicId, DestinationMode, Icr},
    cpu::PinCurrentCpu,
    irq::IrqLine,
    smp,
};

/// Hardware-specific, architecture-dependent CPU ID.
///
/// This is the Local APIC ID in the x86_64 architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HwCpuId(u32);

impl HwCpuId {
    pub(crate) fn read_current(guard: &dyn PinCurrentCpu) -> Self {
        use crate::arch::kernel::apic;

        let apic = apic::get_or_init(guard);
        Self(apic.id())
    }
}

static IPI_IRQ: Once<IrqLine> = Once::new();

/// Initializes global IPI state.
pub(in crate::arch) fn init() {
    let mut irq = IrqLine::alloc().unwrap();
    // SAFETY: This will be called upon an inter-processor interrupt.
    irq.on_active(|f| unsafe { smp::do_inter_processor_call(f) });
    IPI_IRQ.call_once(|| irq);
}

/// Logical destinations use only APIC ID bits 0 through 19. Use physical
/// delivery on topologies with aliases or the reserved broadcast cluster.
pub(crate) fn supports_cluster_delivery(ids: &[HwCpuId]) -> bool {
    matches!(ApicId::from(0), ApicId::X2Apic(_)) && ids.iter().all(|id| id.0 < 0xffff0)
}

pub(crate) fn send_ipis(
    targets: impl Iterator<Item = HwCpuId>,
    clustered: bool,
    guard: &dyn PinCurrentCpu,
) {
    let apic = apic::get_or_init(guard);
    let vector = IPI_IRQ.get().unwrap().num();
    let send = |destination, mode| {
        let icr = Icr::new(
            destination,
            apic::DestinationShorthand::NoShorthand,
            apic::TriggerMode::Edge,
            apic::Level::Assert,
            apic::DeliveryStatus::Idle,
            mode,
            apic::DeliveryMode::Fixed,
            vector,
        );
        // SAFETY: The destination is formed solely from online target IDs,
        // and this vector is reserved for the general IPI handler.
        unsafe { apic.send_ipi(icr) };
    };
    if !clustered {
        for target in targets {
            send(ApicId::from(target.0), DestinationMode::Physical);
        }
        return;
    }

    for_each_cluster(targets, |mask| {
        send(ApicId::X2Apic(mask), DestinationMode::Logical)
    });
}

fn for_each_cluster(targets: impl Iterator<Item = HwCpuId>, mut send: impl FnMut(u32)) {
    let mut mask: u32 = 0;
    for target in targets {
        let logical = ApicId::X2Apic(target.0).x2apic_logical_id();
        if mask != 0 && (mask >> 16) != (logical >> 16) {
            send(mask);
            mask = 0;
        }
        mask |= logical;
    }
    if mask != 0 {
        send(mask);
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::ktest;

    #[ktest]
    fn sparse_logical_destinations_preserve_exact_targets() {
        let mut actual = alloc::vec::Vec::new();
        for_each_cluster([0, 15, 33, 17, 31, 35].into_iter().map(HwCpuId), |m| {
            actual.push(m)
        });
        assert_eq!(actual, [0x8001, 0x20002, 0x18002, 0x20008]);
        actual.clear();
        for_each_cluster(core::iter::empty(), |m| actual.push(m));
        assert!(actual.is_empty());
        assert!(!supports_cluster_delivery(&[HwCpuId(0x100000)]));
        assert!(!supports_cluster_delivery(&[HwCpuId(0xffff0)]));
    }
}
