// SPDX-License-Identifier: MPL-2.0

//! Per-CPU reserve of zeroed frames, replenished before taking PT locks.

use core::cell::RefCell;

use super::{PageTableConfig, PageTableNode, node::PageTableFrameMeta};
use crate::{
    cpu_local, irq,
    mm::{FrameAllocOptions, PagingLevel, UniqueFrame},
    task::disable_preempt,
};

const MAX_POOL_SIZE: usize = 12;
const REFILL_THRESHOLD: usize = 4;

cpu_local! {
    static ZEROED_PT_POOL: RefCell<[Option<UniqueFrame<()>>; MAX_POOL_SIZE]> =
        RefCell::new([const { None }; MAX_POOL_SIZE]);
}

pub(super) fn prefill() {
    let _preempt = disable_preempt();
    let available = {
        let irq = irq::disable_local();
        ZEROED_PT_POOL
            .get_with(&irq)
            .borrow()
            .iter()
            .filter(|f| f.is_some())
            .count()
    };
    if available > REFILL_THRESHOLD {
        return;
    }
    // Allocation/zeroing happens without a PT lock or a live pool borrow.
    // Interrupts may consume reserve frames while this allocation runs.
    let Ok(frames) = FrameAllocOptions::new()
        .zeroed(true)
        .alloc_segment(MAX_POOL_SIZE - available)
    else {
        return;
    };
    for frame in frames {
        let irq = irq::disable_local();
        let pool_ref = ZEROED_PT_POOL.get_with(&irq);
        let mut pool = pool_ref.borrow_mut();
        if let Some(slot) = pool.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(frame.try_into().unwrap());
        }
    }
}

pub(super) fn alloc<C: PageTableConfig>(level: PagingLevel, aux: C::Aux) -> PageTableNode<C> {
    let frame = {
        let irq = irq::disable_local();
        let pool_ref = ZEROED_PT_POOL.get_with(&irq);
        let mut pool = pool_ref.borrow_mut();
        pool.iter_mut().rev().find_map(Option::take)
    };
    // Fresh metadata is essential: neither auxiliary ranges nor queue locks
    // from any previous page-table incarnation may survive reuse.
    let meta = PageTableFrameMeta::new(level, aux);
    match frame {
        Some(frame) => frame.repurpose(meta).into(),
        None => FrameAllocOptions::new()
            .zeroed(true)
            .alloc_frame_with(meta)
            .expect("Failed to allocate a page table node"),
    }
}
