// SPDX-License-Identifier: MPL-2.0

//! Bounded lazy unmap invalidation. A slot's CPU mask is an outstanding-flush
//! mask, never a receipt acknowledgement. Its frame remains RCU-delayed until
//! every CPU has performed the invalidation. Slots are owned by their origin CPU.

use core::{
    cell::{RefCell, SyncUnsafeCell},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use super::{OpsStack, TlbFlushOp};
use crate::{
    cpu::{AtomicCpuSet, CpuId, CpuSet, PinCurrentCpu, all_cpus},
    cpu_local,
    mm::{Frame, frame::meta::AnyFrameMeta},
    sync::RcuDrop,
};

const CAPACITY: usize = 64;
type RetiredFrame = RcuDrop<Frame<dyn AnyFrameMeta>>;

struct Slot {
    pending: AtomicCpuSet,
    op: SyncUnsafeCell<Option<TlbFlushOp>>,
}

cpu_local! {
    static SLOTS: spin::Once<[Slot; CAPACITY]> = spin::Once::new();
    static FRAMES: RefCell<[Option<RetiredFrame>; CAPACITY]> = RefCell::new([const { None }; CAPACITY]);
    // Only the origin writes this bitmap, with local IRQs disabled. A set bit
    // includes completed slots whose retained frame has not yet been recycled.
    static ACTIVE: AtomicU64 = AtomicU64::new(0);
    static TICKS: AtomicUsize = AtomicUsize::new(0);
    static NEXT: AtomicUsize = AtomicUsize::new(0);
}

/// Enqueues an unmap. A full reserve falls back to ordinary shootdown.
pub(super) fn add(
    cpu_set: &CpuSet,
    op: TlbFlushOp,
    frame: RetiredFrame,
) -> Result<(), RetiredFrame> {
    let old;
    {
        let irq = crate::irq::disable_local();
        let cpu = irq.current_cpu();
        let slots = SLOTS.get_on_cpu(cpu).call_once(|| {
            core::array::from_fn(|_| Slot {
                pending: AtomicCpuSet::new(CpuSet::new_empty()),
                op: SyncUnsafeCell::new(None),
            })
        });
        let frames_ref = FRAMES.get_with(&irq);
        let mut frames = frames_ref.borrow_mut();
        let start = NEXT.get_on_cpu(cpu).load(Ordering::Relaxed);
        let Some(idx) = (0..CAPACITY)
            .map(|i| (start + i) % CAPACITY)
            .find(|idx| slots[*idx].pending.load(Ordering::Acquire).is_empty())
        else {
            return Err(frame);
        };
        old = frames[idx].replace(frame);
        // SAFETY: All consumers acknowledged the previous operation after
        // flushing and no longer access it. Only this origin CPU writes slots,
        // with IRQs disabled to exclude nested producers/consumers.
        unsafe {
            *slots[idx].op.get() = Some(op);
        }
        slots[idx].pending.store(cpu_set, Ordering::Release);
        let active = ACTIVE.get_on_cpu(cpu).load(Ordering::Relaxed);
        ACTIVE
            .get_on_cpu(cpu)
            .store(active | (1 << idx), Ordering::Release);
        NEXT.get_on_cpu(cpu)
            .store((idx + 1) % CAPACITY, Ordering::Relaxed);
    }
    // RCU grace-period deferral starts only after all flush acknowledgements.
    drop(old);
    Ok(())
}

/// Drains this CPU's pending invalidations before a context switch, on timer
/// ticks, and when a flusher finishes a transaction. IRQ exclusion prevents
/// nested consumers from acknowledging a slot while the outer reader uses it.
pub(crate) fn do_flush() {
    let irq = crate::irq::disable_local();
    let current = irq.current_cpu();
    for origin in all_cpus() {
        flush_origin(origin, current);
    }
    drop(irq);
    recycle();
}

/// A transaction only has to drain its own origin on the issuing CPU. Timer,
/// context-switch and remote IPI callbacks still drain every origin.
pub(super) fn flush_local() {
    let irq = crate::irq::disable_local();
    let current = irq.current_cpu();
    flush_origin(current, current);
    drop(irq);
    recycle();
}

/// Returns CPUs that have not acknowledged this origin's published operations.
/// The caller remains pinned from enqueue through synchronization. A remote
/// callback may have already drained our slots while handling another origin;
/// those completed CPUs need no additional IPI.
pub(super) fn pending_cpus() -> CpuSet {
    let irq = crate::irq::disable_local();
    let origin = irq.current_cpu();
    let mut pending = CpuSet::new_empty();
    let active = ACTIVE.get_on_cpu(origin).load(Ordering::Relaxed);
    if active == 0 {
        return pending;
    }
    let slots = SLOTS.get_on_cpu(origin).get().unwrap();
    for idx in slot_indices(active) {
        for cpu in slots[idx].pending.load(Ordering::Acquire).iter() {
            pending.add(cpu);
        }
    }
    pending
}

#[cfg(ktest)]
pub(crate) fn pending_cpus_for_test() -> CpuSet {
    pending_cpus()
}

// The caller disables local IRQs throughout operation reads, flushes and ACKs.
fn flush_origin(origin: CpuId, current: CpuId) {
    let active = ACTIVE.get_on_cpu(origin).load(Ordering::Acquire);
    if active == 0 {
        return;
    }
    let Some(slots) = SLOTS.get_on_cpu(origin).get() else {
        return;
    };
    let mut selected = 0;
    let mut ops = OpsStack::new();
    for idx in slot_indices(active) {
        let slot = &slots[idx];
        if slot.pending.contains(current, Ordering::Acquire) {
            // SAFETY: Our still-set pending bit keeps the operation stable.
            if let Some(op) = unsafe { &*slot.op.get() } {
                ops.push(op.clone(), None);
            }
            selected |= 1 << idx;
        }
    }
    ops.flush_all();
    // Release after the architectural flush, so the producer cannot recycle
    // a page while this CPU still has a translation to its old contents.
    for idx in slot_indices(selected) {
        slots[idx].pending.remove(current, Ordering::Release);
    }
}

fn slot_indices(mut bits: u64) -> impl Iterator<Item = usize> {
    core::iter::from_fn(move || {
        if bits == 0 {
            return None;
        }
        let idx = bits.trailing_zeros() as usize;
        bits &= bits - 1;
        Some(idx)
    })
}

fn recycle() {
    let mut retired = [const { None }; CAPACITY];
    {
        let irq = crate::irq::disable_local();
        let cpu = irq.current_cpu();
        let active = ACTIVE.get_on_cpu(cpu).load(Ordering::Relaxed);
        if active == 0 {
            return;
        }
        let Some(slots) = SLOTS.get_on_cpu(cpu).get() else {
            return;
        };
        let frames_ref = FRAMES.get_with(&irq);
        let mut frames = frames_ref.borrow_mut();
        let mut remaining = active;
        for idx in slot_indices(active) {
            if slots[idx].pending.load(Ordering::Acquire).is_empty() {
                retired[idx] = frames[idx].take();
                remaining &= !(1 << idx);
            }
        }
        ACTIVE.get_on_cpu(cpu).store(remaining, Ordering::Release);
    }
    drop(retired);
}

/// Stagger background draining as in the artifact. Transaction synchronization
/// and context switching drain immediately; the timer bounds idle-CPU retention.
pub(crate) fn timer_flush() {
    let irq = crate::irq::disable_local();
    let cpu = irq.current_cpu();
    let tick = TICKS.get_on_cpu(cpu).fetch_add(1, Ordering::Relaxed);
    let due = tick % crate::cpu::num_cpus() == u32::from(cpu) as usize;
    drop(irq);
    if due {
        do_flush();
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{mm::FrameAllocOptions, prelude::*, task::disable_preempt};

    #[ktest]
    fn deferred_unmap_preserves_overflow_fallback_and_reuse() {
        let targets = AtomicCpuSet::new(CpuSet::new_full());
        let mut flusher = super::super::TlbFlusher::new(&targets, disable_preempt());
        flusher.sync_all_deferred_unmaps();
        for _ in 0..3 {
            let frames: alloc::vec::Vec<_> = (0..CAPACITY + 8)
                .map(|_| FrameAllocOptions::new().alloc_frame().unwrap())
                .collect();
            {
                let _irq = crate::irq::disable_local();
                for (idx, frame) in frames.iter().enumerate() {
                    flusher.latr_with(
                        TlbFlushOp::for_single((idx + 1) * crate::mm::PAGE_SIZE),
                        RcuDrop::new(frame.clone().into()),
                    );
                    assert!(frame.reference_count() >= 2);
                }
                // The origin's unacknowledged bit makes overflow deterministic.
                assert_eq!(flusher.ops_stack.frame_keeper.len(), 8);
            }
            assert!(flusher.defer_unmap_flush());
            assert!(flusher.ops_stack.is_empty());
            flusher.sync_all_deferred_unmaps();
            assert!(pending_cpus().is_empty());
        }
    }

    #[ktest]
    fn synchronous_flush_covers_lazy_overflow_and_reuse() {
        let targets = AtomicCpuSet::new(CpuSet::new_full());
        let mut flusher = super::super::TlbFlusher::new(&targets, disable_preempt());
        for _ in 0..3 {
            let frames: alloc::vec::Vec<_> = (0..CAPACITY + 8)
                .map(|_| FrameAllocOptions::new().alloc_frame().unwrap())
                .collect();
            {
                // Prevent the origin from acknowledging these requests while
                // filling the reserve, so the batch also exercises fallback.
                let _irq = crate::irq::disable_local();
                for (idx, frame) in frames.iter().enumerate() {
                    flusher.latr_with(
                        TlbFlushOp::for_single((idx + 1) * crate::mm::PAGE_SIZE),
                        RcuDrop::new(frame.clone().into()),
                    );
                    // No frame can be reclaimed before even the issuing CPU
                    // has performed the flush. This also covers overflow.
                    assert!(frame.reference_count() >= 2);
                }
            }
            flusher.dispatch_tlb_flush();
            flusher.sync_tlb_flush();
            assert!(pending_cpus().is_empty());
        }
    }
}
