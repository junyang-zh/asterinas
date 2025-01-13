// SPDX-License-Identifier: MPL-2.0

//! Managing the kernel heap with the slab allocator or the buddy allocator.

use core::{
    alloc::{AllocError, GlobalAlloc, Layout},
    ptr::NonNull,
};

use slot::HeapSlot;

use crate::panic::abort;

pub mod slab;
pub mod slot;

/// The "trait" for the global heap allocator.
#[derive(Debug, Clone, Copy)]
pub struct GlobalHeapAllocator {
    /// Allocates a heap slot according to the layout.
    pub alloc: fn(core::alloc::Layout) -> Result<HeapSlot, AllocError>,
    /// Deallocates a contiguous range of frames.
    pub dealloc: fn(HeapSlot) -> Result<(), AllocError>,
}

extern "Rust" {
    /// The global heap allocator.
    static __GLOBAL_HEAP_ALLOCATOR: GlobalHeapAllocator;
}

#[alloc_error_handler]
fn handle_alloc_error(layout: core::alloc::Layout) -> ! {
    log::error!("Heap allocation error, layout = {:?}", layout);
    abort();
}

#[global_allocator]
static HEAP_ALLOCATOR: AllocDispatch = AllocDispatch;

struct AllocDispatch;

unsafe impl GlobalAlloc for AllocDispatch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let alloc_fn = unsafe { __GLOBAL_HEAP_ALLOCATOR.alloc };

        alloc_fn(layout).map_or(core::ptr::null_mut(), |slot| slot.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let dealloc_fn = unsafe { __GLOBAL_HEAP_ALLOCATOR.dealloc };

        let slot = HeapSlot::new(NonNull::new_unchecked(ptr), layout.size());
        if dealloc_fn(slot).is_err() {
            log::error!(
                "Heap deallocation error, ptr = {:p}, layout = {:?}",
                ptr,
                layout,
            );
            abort();
        }
    }
}
