// SPDX-License-Identifier: MPL-2.0

//! A fixed-size local cache for frame allocation.

use core::{alloc::Layout, cell::RefCell};

use ostd::{
    cpu_local,
    irq::DisabledLocalIrqGuard,
    mm::{PAGE_SIZE, Paddr},
};

cpu_local! {
    static CACHE: RefCell<CacheOfSizes> = RefCell::new(CacheOfSizes::new());
}

struct CacheOfSizes {
    cache1: CacheArray<1, 12>,
    cache2: CacheArray<2, 6>,
    cache3: CacheArray<3, 6>,
    cache4: CacheArray<4, 6>,
}

/// A fixed-size local cache for frame allocation.
///
/// Each cache array contains at most `COUNT` segments. Each segment contains
/// `NR_CONT_FRAMES` contiguous frames.
struct CacheArray<const NR_CONT_FRAMES: usize, const COUNT: usize> {
    inner: [Option<Paddr>; COUNT],
    size: usize,
}

impl<const NR_CONT_FRAMES: usize, const COUNT: usize> CacheArray<NR_CONT_FRAMES, COUNT> {
    const fn new() -> Self {
        Self {
            inner: [const { None }; COUNT],
            size: 0,
        }
    }

    /// The size of the segments that this cache manages.
    const fn segment_size() -> usize {
        NR_CONT_FRAMES * PAGE_SIZE
    }

    /// Allocates a segment of frames.
    ///
    /// It may allocate directly from this cache. If the cache is empty, it
    /// will fill the cache.
    fn alloc(&mut self, mut allocate: impl FnMut(Layout) -> Option<Paddr>) -> Option<Paddr> {
        if let Some(frame) = self.pop_front() {
            return Some(frame);
        }

        let nr_to_alloc = COUNT * 2 / 3;
        let refill =
            Layout::from_size_align(nr_to_alloc * Self::segment_size(), PAGE_SIZE).unwrap();
        let Some(allocated) = allocate(refill) else {
            // A fragmented pool can still satisfy the requested segment.
            return allocate(Layout::from_size_align(Self::segment_size(), PAGE_SIZE).unwrap());
        };

        for i in 1..nr_to_alloc {
            self.push_front(allocated + i * Self::segment_size());
        }

        Some(allocated)
    }

    /// Deallocates a segment of frames.
    ///
    /// It may deallocate directly to this cache. If the cache is full, it will
    /// deallocate to the global pool.
    fn dealloc(&mut self, guard: &DisabledLocalIrqGuard, addr: Paddr) {
        if self.push_front(addr).is_none() {
            let nr_to_dealloc = COUNT * 2 / 3 + 1;

            let segments = (0..nr_to_dealloc).map(|i| {
                if i == 0 {
                    (addr, Self::segment_size())
                } else {
                    (self.pop_front().unwrap(), Self::segment_size())
                }
            });

            super::pools::dealloc(guard, segments);
        };
    }

    fn push_front(&mut self, frame: Paddr) -> Option<()> {
        if self.size == COUNT {
            return None;
        }

        self.inner[self.size] = Some(frame);
        self.size += 1;
        Some(())
    }

    fn pop_front(&mut self) -> Option<Paddr> {
        if self.size == 0 {
            return None;
        }

        let frame = self.inner[self.size - 1].take().unwrap();
        self.size -= 1;
        Some(frame)
    }
}

impl CacheOfSizes {
    const fn new() -> Self {
        Self {
            cache1: CacheArray::new(),
            cache2: CacheArray::new(),
            cache3: CacheArray::new(),
            cache4: CacheArray::new(),
        }
    }
}

pub(super) fn alloc(guard: &DisabledLocalIrqGuard, layout: Layout) -> Option<Paddr> {
    let nr_frames = layout.size() / PAGE_SIZE;
    // Entries returned by OSTD may start at any page boundary, including
    // subranges of an earlier allocation. Only the buddy pools honor a
    // stricter requested alignment.
    if layout.align() > PAGE_SIZE {
        return super::pools::alloc(guard, layout);
    }

    let cache_cell = CACHE.get_with(guard);
    let mut cache = cache_cell.borrow_mut();

    let allocate = |layout| super::pools::alloc(guard, layout);
    match nr_frames {
        1 => cache.cache1.alloc(allocate),
        2 => cache.cache2.alloc(allocate),
        3 => cache.cache3.alloc(allocate),
        4 => cache.cache4.alloc(allocate),
        _ => super::pools::alloc(guard, layout),
    }
}

pub(super) fn dealloc(guard: &DisabledLocalIrqGuard, addr: Paddr, size: usize) {
    let nr_frames = size / PAGE_SIZE;
    if nr_frames > 4 {
        super::pools::dealloc(guard, [(addr, size)].into_iter());
        return;
    }

    let cache_cell = CACHE.get_with(guard);
    let mut cache = cache_cell.borrow_mut();

    match nr_frames {
        1 => cache.cache1.dealloc(guard, addr),
        2 => cache.cache2.dealloc(guard, addr),
        3 => cache.cache3.dealloc(guard, addr),
        4 => cache.cache4.dealloc(guard, addr),
        _ => super::pools::dealloc(guard, [(addr, size)].into_iter()),
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn fragmented_pool_can_supply_a_single_cached_segment() {
        let mut cache = CacheArray::<3, 6>::new();
        let mut requests = alloc::vec::Vec::new();
        let supplied = cache.alloc(|layout| {
            requests.push(layout.size());
            (layout.size() == 3 * PAGE_SIZE).then_some(16 * PAGE_SIZE)
        });
        assert_eq!(requests, [12 * PAGE_SIZE, 3 * PAGE_SIZE]);
        assert_eq!(supplied, Some(16 * PAGE_SIZE));
        assert!(cache.pop_front().is_none());
        assert!(cache.alloc(|_| None).is_none());

        let mut calls = 0;
        let mut allocate = |layout: Layout| {
            calls += 1;
            assert_eq!(layout.size(), 12 * PAGE_SIZE);
            Some(32 * PAGE_SIZE)
        };
        let mut pages = core::array::from_fn::<_, 4, _>(|_| cache.alloc(&mut allocate).unwrap());
        pages.sort_unstable();
        assert_eq!(pages, [32, 35, 38, 41].map(|index| index * PAGE_SIZE));
        assert_eq!(calls, 1);
    }
}
