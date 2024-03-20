// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;

use spin::Once;

use crate::{sync::SpinLock, trap::irq::SystemIrqLine, util::recycle_allocator::RecycleAllocator};

pub(crate) fn enable_local() {
    x86_64::instructions::interrupts::enable();
    // When emulated with QEMU, interrupts may not be delivered if a STI instruction is immediately
    // followed by a RET instruction. It is a BUG of QEMU, see the following patch for details.
    // https://lore.kernel.org/qemu-devel/20231210190147.129734-2-lrh2000@pku.edu.cn/
    x86_64::instructions::nop();
}

pub(crate) fn disable_local() {
    x86_64::instructions::interrupts::disable();
}

pub(crate) fn is_local_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}

pub(crate) static IRQ_NUM_ALLOCATOR: SpinLock<RecycleAllocator> =
    SpinLock::new(RecycleAllocator::with_start_max(32, 256));

pub(crate) static IRQ_LIST: Once<Vec<SystemIrqLine>> = Once::new();

pub(crate) fn init() {
    let mut list: Vec<SystemIrqLine> = Vec::new();
    for i in 0..256 {
        list.push(SystemIrqLine {
            irq_num: i as u8,
            callback_list: SpinLock::new(Vec::new()),
        });
    }
    IRQ_LIST.call_once(|| list);
}
