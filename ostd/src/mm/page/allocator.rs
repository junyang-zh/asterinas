// SPDX-License-Identifier: MPL-2.0

//! The physical page memory allocator.
//!
//! TODO: Decouple it with the frame allocator in [`crate::mm::frame::options`] by
//! allocating pages rather untyped memory from this module.

use alloc::vec::Vec;
use core::{cell::RefCell, sync::atomic::Ordering};

use align_ext::AlignExt;
use buddy_system_allocator::FrameAllocator;
use log::info;
use spin::Once;

use super::{cont_pages::ContPages, meta::PageMeta, Page};
use crate::{
    boot::memory_region::MemoryRegionType,
    cpu_local,
    mm::{Paddr, PAGE_SIZE},
    sync::SpinLock,
};

/// FrameAllocator with a counter for allocated memory
pub(in crate::mm) struct CountingFrameAllocator {
    allocator: FrameAllocator,
    total: usize,
    allocated: usize,
}

impl CountingFrameAllocator {
    pub fn new(allocator: FrameAllocator, total: usize) -> Self {
        CountingFrameAllocator {
            allocator,
            total,
            allocated: 0,
        }
    }

    pub fn alloc(&mut self, count: usize) -> Option<usize> {
        match self.allocator.alloc(count) {
            Some(value) => {
                self.allocated += count * PAGE_SIZE;
                Some(value)
            }
            None => None,
        }
    }

    pub fn dealloc(&mut self, start_frame: usize, count: usize) {
        self.allocator.dealloc(start_frame, count);
        self.allocated -= count * PAGE_SIZE;
    }

    pub fn mem_total(&self) -> usize {
        self.total
    }

    pub fn mem_available(&self) -> usize {
        self.total - self.allocated
    }
}

pub(in crate::mm) static PAGE_ALLOCATOR: Once<SpinLock<CountingFrameAllocator>> = Once::new();

cpu_local! {
    static LOCAL_CACHE: RefCell<LocalCache> = RefCell::new(LocalCache::new());
}

const LOCAL_CACHE_SIZE: usize = 64;
const LOCAL_LOW_WATERMARK: usize = LOCAL_CACHE_SIZE / 2;
const LOCAL_HIGH_WATERMARK: usize = LOCAL_CACHE_SIZE / 4 * 3;

struct LocalCache {
    cache_stack: [Option<Paddr>; LOCAL_CACHE_SIZE],
    top: usize,
}

impl LocalCache {
    pub const fn new() -> Self {
        LocalCache {
            cache_stack: [None; LOCAL_CACHE_SIZE],
            top: 0,
        }
    }

    pub fn alloc(&mut self) -> Paddr {
        if self.top == 0 {
            return self.alloc_slow();
        }
        self.top -= 1;
        self.cache_stack[self.top].take().unwrap()
    }

    pub fn dealloc(&mut self, paddr: Paddr) {
        if self.top == LOCAL_CACHE_SIZE {
            self.dealloc_slow(paddr);
            return;
        }
        self.cache_stack[self.top] = Some(paddr);
        self.top += 1;
    }

    fn alloc_slow(&mut self) -> Paddr {
        let paddr = PAGE_ALLOCATOR
            .get()
            .unwrap()
            .lock()
            .alloc(LOCAL_LOW_WATERMARK)
            .unwrap()
            * PAGE_SIZE;
        for i in 0..LOCAL_LOW_WATERMARK {
            self.cache_stack[i] = Some(paddr + i * PAGE_SIZE);
        }
        self.top = LOCAL_LOW_WATERMARK - 1;
        self.cache_stack[self.top].unwrap()
    }

    fn dealloc_slow(&mut self, paddr: Paddr) {
        let mut allocator = PAGE_ALLOCATOR.get().unwrap().lock();
        let frame_num = paddr / PAGE_SIZE;
        allocator.dealloc(frame_num, 1);
        for i in LOCAL_HIGH_WATERMARK..LOCAL_CACHE_SIZE {
            let frame_num = self.cache_stack[i].take().unwrap() / PAGE_SIZE;
            allocator.dealloc(frame_num, 1);
        }
        self.top = LOCAL_HIGH_WATERMARK;
    }
}

/// Allocate a single page.
///
/// The metadata of the page is initialized with the given metadata.
pub(crate) fn alloc_single<M: PageMeta>(metadata: M) -> Option<Page<M>> {
    if !crate::INITIALIZED.load(Ordering::Acquire) {
        let mut allocator = PAGE_ALLOCATOR.get().unwrap().lock();
        return allocator.alloc(1).map(|idx| {
            let paddr = idx * PAGE_SIZE;
            Page::from_unused(paddr, metadata)
        });
    }

    let irq_guard = crate::trap::disable_local();
    let local_guard = LOCAL_CACHE.get_with(&irq_guard);
    let pa = local_guard.borrow_mut().alloc();

    Some(Page::from_unused(pa, metadata))
}

pub(crate) fn dealloc_single(paddr: Paddr) {
    if !crate::INITIALIZED.load(Ordering::Acquire) {
        PAGE_ALLOCATOR
            .get()
            .unwrap()
            .lock()
            .dealloc(paddr / PAGE_SIZE, 1);
        return;
    }

    let irq_guard = crate::trap::disable_local();
    let local_guard = LOCAL_CACHE.get_with(&irq_guard);
    local_guard.borrow_mut().dealloc(paddr);
}

/// Allocate a contiguous range of pages of a given length in bytes.
///
/// The caller must provide a closure to initialize metadata for all the pages.
/// The closure receives the physical address of the page and returns the
/// metadata, which is similar to [`core::array::from_fn`].
///
/// # Panics
///
/// The function panics if the length is not base-page-aligned.
pub(crate) fn alloc_contiguous<M: PageMeta, F>(len: usize, metadata_fn: F) -> Option<ContPages<M>>
where
    F: FnMut(Paddr) -> M,
{
    assert!(len % PAGE_SIZE == 0);
    PAGE_ALLOCATOR
        .get()
        .unwrap()
        .disable_irq()
        .lock()
        .alloc(len / PAGE_SIZE)
        .map(|start| {
            ContPages::from_unused(start * PAGE_SIZE..start * PAGE_SIZE + len, metadata_fn)
        })
}

/// Allocate pages.
///
/// The allocated pages are not guaranteed to be contiguous.
/// The total length of the allocated pages is `len`.
///
/// The caller must provide a closure to initialize metadata for all the pages.
/// The closure receives the physical address of the page and returns the
/// metadata, which is similar to [`core::array::from_fn`].
///
/// # Panics
///
/// The function panics if the length is not base-page-aligned.
pub(crate) fn alloc<M: PageMeta, F>(len: usize, mut metadata_fn: F) -> Option<Vec<Page<M>>>
where
    F: FnMut(Paddr) -> M,
{
    assert!(len % PAGE_SIZE == 0);
    let nframes = len / PAGE_SIZE;
    let mut allocator = PAGE_ALLOCATOR.get().unwrap().disable_irq().lock();
    let mut vector = Vec::new();
    for _ in 0..nframes {
        let paddr = allocator.alloc(1)? * PAGE_SIZE;
        let page = Page::<M>::from_unused(paddr, metadata_fn(paddr));
        vector.push(page);
    }
    Some(vector)
}

pub(crate) fn init() {
    let regions = crate::boot::memory_regions();
    let mut total: usize = 0;
    let mut allocator = FrameAllocator::<32>::new();
    for region in regions.iter() {
        if region.typ() == MemoryRegionType::Usable {
            // Make the memory region page-aligned, and skip if it is too small.
            let start = region.base().align_up(PAGE_SIZE) / PAGE_SIZE;
            let region_end = region.base().checked_add(region.len()).unwrap();
            let end = region_end.align_down(PAGE_SIZE) / PAGE_SIZE;
            if end <= start {
                continue;
            }
            // Add global free pages to the frame allocator.
            allocator.add_frame(start, end);
            total += (end - start) * PAGE_SIZE;
            info!(
                "Found usable region, start:{:x}, end:{:x}",
                region.base(),
                region.base() + region.len()
            );
        }
    }
    let counting_allocator = CountingFrameAllocator::new(allocator, total);
    PAGE_ALLOCATOR.call_once(|| SpinLock::new(counting_allocator));
}
