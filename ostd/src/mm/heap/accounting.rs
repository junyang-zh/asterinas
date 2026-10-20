// SPDX-License-Identifier: MPL-2.0

//! Diagnostic allocation accounting. This module is absent from production builds.
//! Charged bytes are live allocator slots, not backing slabs or allocator reserves.

use alloc::{alloc::Global, sync::Arc};
use core::{alloc::{AllocError, Allocator, Layout}, ptr::NonNull, sync::atomic::{AtomicUsize, Ordering}};

/// Live allocation totals for one collection allocator.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllocationSnapshot {
    pub allocations: usize,
    pub requested_bytes: usize,
    pub charged_bytes: usize,
}

#[derive(Debug, Default)]
struct Counters {
    allocations: AtomicUsize,
    requested_bytes: AtomicUsize,
    charged_bytes: AtomicUsize,
}

/// An allocator shared only by clones of the same instrumented collection.
/// The diagnostic Arc itself is deliberately excluded from collection charges.
#[derive(Clone, Debug)]
pub struct AccountingAllocator(Arc<Counters>);

impl AccountingAllocator {
    pub fn new() -> Self { Self(Arc::new(Counters::default())) }

    /// Call while the collection is locked, so its allocations cannot change.
    pub fn snapshot(&self) -> AllocationSnapshot {
        AllocationSnapshot {
            allocations: self.0.allocations.load(Ordering::Relaxed),
            requested_bytes: self.0.requested_bytes.load(Ordering::Relaxed),
            charged_bytes: self.0.charged_bytes.load(Ordering::Relaxed),
        }
    }
}

/// The actual slot size selected by the active kernel heap's layout map.
pub fn charged_size(layout: Layout) -> usize {
    if layout.size() == 0 { 0 } else { super::slot_size_from_layout(layout).unwrap().size() }
}

// SAFETY: Allocation and deallocation are delegated to Global with the original
// pointer/layout. Clones retain the same counter owner and do not alter allocation lifetimes.
unsafe impl Allocator for AccountingAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let ptr = Global.allocate(layout)?;
        self.0.allocations.fetch_add(1, Ordering::Relaxed);
        self.0.requested_bytes.fetch_add(layout.size(), Ordering::Relaxed);
        self.0.charged_bytes.fetch_add(charged_size(layout), Ordering::Relaxed);
        Ok(ptr)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: The caller supplies a currently live allocation with its original layout.
        unsafe { Global.deallocate(ptr, layout) };
        self.0.allocations.fetch_sub(1, Ordering::Relaxed);
        self.0.requested_bytes.fetch_sub(layout.size(), Ordering::Relaxed);
        self.0.charged_bytes.fetch_sub(charged_size(layout), Ordering::Relaxed);
    }
}

#[cfg(ktest)]
mod tests {
    use alloc::vec::Vec;
    use super::*;
    use crate::prelude::ktest;

    #[ktest]
    fn tracked_collection_growth_and_drop() {
        let allocator = AccountingAllocator::new();
        {
            let mut values = Vec::new_in(allocator.clone());
            for value in 0..1024u64 { values.push(value); }
            let snapshot = allocator.snapshot();
            assert_eq!(snapshot.allocations, 1);
            assert!(snapshot.requested_bytes >= 1024 * core::mem::size_of::<u64>());
            assert!(snapshot.charged_bytes >= snapshot.requested_bytes);
            values.truncate(16);
            values.shrink_to_fit();
            assert!(allocator.snapshot().requested_bytes < snapshot.requested_bytes);
        }
        let snapshot = allocator.snapshot();
        assert_eq!(snapshot.allocations, 0);
        assert_eq!(snapshot.requested_bytes, 0);
        assert_eq!(snapshot.charged_bytes, 0);
    }
}
