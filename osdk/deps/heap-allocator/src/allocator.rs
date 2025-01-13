// SPDX-License-Identifier: MPL-2.0

//! A global allocator implementation of many slab caches.

use core::alloc::{AllocError, Layout};

use ostd::{
    mm::heap::slot::HeapSlot,
    sync::{LocalIrqDisabled, SpinLock},
};

use crate::cache::SlabCache;

struct HeapCache {
    slab8: SlabCache<8>,
    slab16: SlabCache<16>,
    slab32: SlabCache<32>,
    slab64: SlabCache<64>,
    slab128: SlabCache<128>,
    slab256: SlabCache<256>,
    slab512: SlabCache<512>,
    slab1024: SlabCache<1024>,
    slab2048: SlabCache<2048>,
    slab4096: SlabCache<4096>,
}

impl HeapCache {
    const fn new() -> Self {
        Self {
            slab8: SlabCache::new(),
            slab16: SlabCache::new(),
            slab32: SlabCache::new(),
            slab64: SlabCache::new(),
            slab128: SlabCache::new(),
            slab256: SlabCache::new(),
            slab512: SlabCache::new(),
            slab1024: SlabCache::new(),
            slab2048: SlabCache::new(),
            slab4096: SlabCache::new(),
        }
    }

    fn alloc(&mut self, class: CommonSizeClasses) -> Result<HeapSlot, AllocError> {
        match class {
            CommonSizeClasses::Bytes8 => self.slab8.alloc(),
            CommonSizeClasses::Bytes16 => self.slab16.alloc(),
            CommonSizeClasses::Bytes32 => self.slab32.alloc(),
            CommonSizeClasses::Bytes64 => self.slab64.alloc(),
            CommonSizeClasses::Bytes128 => self.slab128.alloc(),
            CommonSizeClasses::Bytes256 => self.slab256.alloc(),
            CommonSizeClasses::Bytes512 => self.slab512.alloc(),
            CommonSizeClasses::Bytes1024 => self.slab1024.alloc(),
            CommonSizeClasses::Bytes2048 => self.slab2048.alloc(),
            CommonSizeClasses::Bytes4096 => self.slab4096.alloc(),
        }
    }
}

static GLOBAL_POOL: SpinLock<HeapCache, LocalIrqDisabled> = SpinLock::new(HeapCache::new());

/// Allocates a heap slot according to the layout.
pub fn alloc(layout: Layout) -> Result<HeapSlot, AllocError> {
    if layout.size() > 4096 {
        return HeapSlot::alloc_large(layout.size());
    }

    let size_class = CommonSizeClasses::from_slot_size(layout.size());

    let mut pool = GLOBAL_POOL.lock();

    pool.alloc(size_class)
}

/// Deallocates a heap slot.
pub fn dealloc(slot: HeapSlot) -> Result<(), AllocError> {
    if slot.size() > 4096 {
        slot.dealloc_large();
        return Ok(());
    }

    let size_class = CommonSizeClasses::from_slot_size(slot.size());
    let mut global_pool = GLOBAL_POOL.lock();

    match size_class {
        CommonSizeClasses::Bytes8 => global_pool.slab8.dealloc(slot),
        CommonSizeClasses::Bytes16 => global_pool.slab16.dealloc(slot),
        CommonSizeClasses::Bytes32 => global_pool.slab32.dealloc(slot),
        CommonSizeClasses::Bytes64 => global_pool.slab64.dealloc(slot),
        CommonSizeClasses::Bytes128 => global_pool.slab128.dealloc(slot),
        CommonSizeClasses::Bytes256 => global_pool.slab256.dealloc(slot),
        CommonSizeClasses::Bytes512 => global_pool.slab512.dealloc(slot),
        CommonSizeClasses::Bytes1024 => global_pool.slab1024.dealloc(slot),
        CommonSizeClasses::Bytes2048 => global_pool.slab2048.dealloc(slot),
        CommonSizeClasses::Bytes4096 => global_pool.slab4096.dealloc(slot),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommonSizeClasses {
    Bytes8,
    Bytes16,
    Bytes32,
    Bytes64,
    Bytes128,
    Bytes256,
    Bytes512,
    Bytes1024,
    Bytes2048,
    Bytes4096,
}

impl CommonSizeClasses {
    fn from_slot_size(slot_size: usize) -> Self {
        match slot_size {
            0..=8 => CommonSizeClasses::Bytes8,
            9..=16 => CommonSizeClasses::Bytes16,
            17..=32 => CommonSizeClasses::Bytes32,
            33..=64 => CommonSizeClasses::Bytes64,
            65..=128 => CommonSizeClasses::Bytes128,
            129..=256 => CommonSizeClasses::Bytes256,
            257..=512 => CommonSizeClasses::Bytes512,
            513..=1024 => CommonSizeClasses::Bytes1024,
            1025..=2048 => CommonSizeClasses::Bytes2048,
            2049..=4096 => CommonSizeClasses::Bytes4096,
            _ => panic!("Invalid slot size"),
        }
    }
}
