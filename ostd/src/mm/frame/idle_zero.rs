// SPDX-License-Identifier: MPL-2.0

//! CPU-local demand for zero-filled fault frames, serviced by the idle task.

use core::{alloc::Layout, sync::atomic::{AtomicBool, Ordering}};

use super::{Frame, allocator::get_global_frame_allocator, segment::Segment};
use crate::{
    cpu::{PinCurrentCpu, all_cpus},
    cpu_local,
    mm::{PAGE_SIZE, paddr_to_vaddr},
    sync::SpinLock,
    task::disable_preempt,
};

const MAX_FRAMES: usize = 32;
struct Reserve {
    frames: [Option<Frame<()>>; MAX_FRAMES],
    len: usize,
    target: usize,
}
cpu_local! {
    static RESERVE: SpinLock<Reserve> = SpinLock::new(Reserve {
        frames: [const { None }; MAX_FRAMES], len: 0, target: 0,
    });
    static NEEDS_FILL: AtomicBool = AtomicBool::new(false);
}
static STARTED: AtomicBool = AtomicBool::new(false);

pub(super) fn take() -> Option<Frame<()>> {
    if !STARTED.load(Ordering::Relaxed) {
        STARTED.store(true, Ordering::Relaxed);
    }
    let pin = disable_preempt();
    let cpu = pin.current_cpu();
    let mut pool = RESERVE.get_on_cpu(cpu).disable_irq().lock();
    let frame = if let Some(last) = pool.len.checked_sub(1) {
        pool.len = last;
        pool.frames[last].take()
    } else {
        pool.target = (pool.target + 1).min(MAX_FRAMES);
        None
    };
    NEEDS_FILL.get_on_cpu(cpu).store(true, Ordering::Relaxed);
    frame
}

// Bound work in an idle iteration, even if another task wakes during refill.
const REFILL_LIMIT: usize = 4;

pub(super) fn fill_batch() -> bool {
    let cpu = { let pin = disable_preempt(); pin.current_cpu() };
    let needs_fill = NEEDS_FILL.get_on_cpu(cpu);
    if !needs_fill.load(Ordering::Relaxed) {
        return false;
    }
    let reserve = RESERVE.get_on_cpu(cpu);
    let count = {
        let pool = reserve.disable_irq().lock();
        pool.target.saturating_sub(pool.len).min(REFILL_LIMIT)
    };
    if count == 0 {
        return false;
    }

    // The speculative request may use fewer pages when memory is fragmented.
    // It never drains another CPU's reserve to satisfy this idle allocation.
    let allocator = get_global_frame_allocator();
    let allocate = |count| {
        let size = count * PAGE_SIZE;
        let layout = Layout::from_size_align(size, PAGE_SIZE).unwrap();
        allocator.alloc(layout).map(|addr| (addr, size))
    };
    let Some((addr, size)) = allocate(count).or_else(|| {
        if count > 1 { allocate(1) } else { None }
    }) else { return false; };
    let mut frames = Segment::from_unused(addr..addr+size, |_| ()).unwrap();
    // SAFETY: The allocator granted exclusive ownership of this entire range.
    // Every byte is initialized before even the first frame becomes visible.
    unsafe { core::ptr::write_bytes(paddr_to_vaddr(addr) as *mut u8, 0, size) };

    let mut filled = false;
    {
        let mut pool = reserve.disable_irq().lock();
        while pool.len < pool.target {
            let Some(frame) = frames.next() else { break; };
            let index = pool.len;
            pool.frames[index] = Some(frame);
            pool.len += 1;
            filled = true;
        }
        needs_fill.store(pool.len < pool.target, Ordering::Relaxed);
    }
    // A concurrent physical-memory reclaim can reset the target. Release any
    // unconsumed frames outside the reserve lock.
    drop(frames);
    filled
}

pub(super) fn reclaim() -> bool {
    if !STARTED.load(Ordering::Relaxed) {
        return false;
    }
    let mut reclaimed = false;
    for cpu in all_cpus() {
        let frames = {
            let mut pool = RESERVE.get_on_cpu(cpu).disable_irq().lock();
            pool.target = 0;
            pool.len = 0;
            NEEDS_FILL.get_on_cpu(cpu).store(false, Ordering::Relaxed);
            core::mem::replace(&mut pool.frames, [const { None }; MAX_FRAMES])
        };
        reclaimed |= frames.iter().any(Option::is_some);
        drop(frames);
    }
    reclaimed
}

#[cfg(ktest)]
#[crate::prelude::ktest(expect_redundant_test_prefix)]
fn test_idle_fault_frames_are_zero_and_reclaimable() {
    use crate::{mm::VmIo, prelude::*};
    let _pin = disable_preempt();
    reclaim();
    assert!(take().is_none());
    assert!(take().is_none());
    assert!(fill_batch());
    assert!(!fill_batch());
    let frame = take().unwrap();
    let mut bytes = [0xff; 64];
    for pos in (0..PAGE_SIZE).step_by(bytes.len()) {
        frame.read_bytes(pos, &mut bytes).unwrap();
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
    frame.write_bytes(0, &[71]).unwrap();
    assert!(reclaim());
    assert!(take().is_none());
    let mut check = [0];
    frame.read_bytes(0, &mut check).unwrap();
    assert_eq!(check, [71]);
}

#[cfg(ktest)]
#[crate::prelude::ktest]
fn idle_refill_is_bounded_and_scrubs_the_entire_batch() {
    use crate::mm::VmIo;
    let _pin = disable_preempt();
    reclaim();
    for _ in 0..2*REFILL_LIMIT { assert!(take().is_none()); }
    assert!(fill_batch());
    let zero = [0u8; 128];
    let mut kept = alloc::vec::Vec::new();
    for _ in 0..REFILL_LIMIT {
        let frame = take().unwrap();
        for offset in (0..PAGE_SIZE).step_by(zero.len()) {
            let mut bytes = [0xff; 128];
            frame.read_bytes(offset, &mut bytes).unwrap();
            assert_eq!(bytes,zero);
        }
        frame.write_bytes(0,&[44]).unwrap();
        kept.push(frame);
    }
    assert!(take().is_none());
    assert!(fill_batch());
    assert!(reclaim());
    for frame in kept {
        let mut byte=[0];
        frame.read_bytes(0,&mut byte).unwrap();
        assert_eq!(byte,[44]);
    }
}
