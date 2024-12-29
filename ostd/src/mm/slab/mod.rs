// SPDX-License-Identifier: MPL-2.0

use core::{
    ptr::NonNull,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

use super::{
    frame::{
        meta::{mapping, AnyFrameMeta, MetaSlot},
        Segment,
    },
    kspace::LINEAR_MAPPING_BASE_VADDR,
    FrameAllocOptions, Paddr, PAGE_SIZE,
};
use crate::{arch::mm::PagingConsts, mm::paddr_to_vaddr};
/// A slab.
///
/// The slot size is the maximum size and alignment of the objects that can be
/// allocated from the slab. The slab is divided into slots of this size.
///
/// The size of the slot cannot be smaller than the size of [`usize`] and must
/// be a power of two. The size of the slab should be larger than the slot
/// size and [`PAGE_SIZE`].
pub struct Slab<const SLOT_SIZE: usize>(Segment<SlabMeta<SLOT_SIZE>>);

/// Frame metadata of a slab.
///
/// Each slab is backed by a [`Segment`]. All metadata of frames in this segment
/// is of this type.
#[derive(Debug)]
enum SlabMeta<const SLOT_SIZE: usize> {
    /// The head frame of the slab's backing segment.
    HeadFrame {
        /// The total size of the slab in bytes.
        ///
        /// Slabs are backed by segments, this field is the size of the segment.
        segment_size: usize,
        /// Points to the first free slot, or null if the slab is full.
        free_list_head: AtomicPtr<usize>,
        /// The number of free slots in the slab.
        nr_free_slots: AtomicUsize,

        /// Slab cache linked list link.
        next_slab: AtomicPtr<MetaSlot>,
        /// The pointer to the linked list that this slab resides.
        in_list: AtomicPtr<SlabList<SLOT_SIZE>>,
    },
    /// Frames other than the head of the slab's backing segment.
    TailFrame { segment_head: Paddr },
}

unsafe impl<const SLOT_SIZE: usize> AnyFrameMeta for SlabMeta<SLOT_SIZE> {}

impl<const SLOT_SIZE: usize> Slab<SLOT_SIZE> {
    /// Allocates a new slab of the given size.
    ///
    /// If the size is less than `SLOT_SIZE` or [`PAGE_SIZE`], the size will be
    /// the maximum of the two.
    pub fn new(size: usize) -> crate::prelude::Result<Self> {
        let size = size.max(SLOT_SIZE);
        let mut segment_head = None;
        let seg = FrameAllocOptions::new().zeroed(false).alloc_segment_with(
            size.div_ceil(PAGE_SIZE),
            |paddr| {
                if let Some(segment_head) = segment_head {
                    SlabMeta::TailFrame { segment_head }
                } else {
                    segment_head = Some(paddr);
                    let vaddr = paddr_to_vaddr(paddr);
                    SlabMeta::HeadFrame {
                        segment_size: size,
                        free_list_head: AtomicPtr::new(vaddr as *mut usize),
                        nr_free_slots: AtomicUsize::new(size / SLOT_SIZE),

                        next_slab: AtomicPtr::new(core::ptr::null_mut()),
                        in_list: AtomicPtr::new(core::ptr::null_mut()),
                    }
                }
            },
        )?;

        let vaddr = {
            let paddr = segment_head.unwrap();
            debug_assert_eq!(paddr, seg.start_paddr());
            paddr_to_vaddr(paddr)
        };

        // Initialize the free list.
        // If a slot is free, the slot stores the address of the next free slot.
        // TODO: use a coloring scheme instead of doing it linearly.
        for slot_offset in (0..size).step_by(SLOT_SIZE) {
            let slot_addr = vaddr + slot_offset;
            let next_slot_addr = if slot_offset == size - SLOT_SIZE {
                core::ptr::null_mut::<usize>() as usize
            } else {
                slot_addr + SLOT_SIZE
            };
            let slot_ptr = slot_addr as *mut usize;
            unsafe {
                *slot_ptr = next_slot_addr;
            }
        }

        Ok(Self(seg))
    }

    /// Allocates a slot from the slab.
    pub fn alloc(&mut self) -> Option<SlabSlot<SLOT_SIZE>> {
        let SlabMeta::HeadFrame {
            free_list_head,
            nr_free_slots,
            ..
        } = self.0.meta(0)
        else {
            panic!("Invalid slab meta");
        };
        // Set the head to the pointer stored in the current head slot and
        // return the current head.
        free_list_head
            .fetch_update(Ordering::Release, Ordering::Acquire, |head| {
                if head.is_null() {
                    None
                } else {
                    let next = unsafe { *head };
                    nr_free_slots.fetch_sub(1, Ordering::Release);
                    Some(next as *mut usize)
                }
            })
            .map(|addr| SlabSlot {
                addr: NonNull::new(addr as *mut u8).unwrap(),
            })
            .ok()
    }
}

/// A slot in a slab.
pub struct SlabSlot<const SLOT_SIZE: usize> {
    /// The address of the slot.
    addr: NonNull<u8>,
}

impl<const SLOT_SIZE: usize> SlabSlot<SLOT_SIZE> {
    /// Returns a reference to the head metadata of the slab.
    ///
    /// Since the slab won't be dropped until all the slots are deallocated,
    /// this method is safe.
    fn find_slab_head(&self) -> &SlabMeta<SLOT_SIZE> {
        let reside_frame: Paddr =
            (self.addr.as_ptr() as usize - LINEAR_MAPPING_BASE_VADDR) / PAGE_SIZE * PAGE_SIZE;
        let meta_slot =
            mapping::frame_to_meta::<PagingConsts>(reside_frame) as *const SlabMeta<SLOT_SIZE>;
        // SAFETY: The metadata must be slab metadata and must be valid.
        let meta = unsafe { &*meta_slot };
        match meta {
            SlabMeta::HeadFrame { .. } => meta,
            SlabMeta::TailFrame { segment_head } => {
                let meta_slot = mapping::frame_to_meta::<PagingConsts>(*segment_head)
                    as *const SlabMeta<SLOT_SIZE>;
                // SAFETY: The head metadata must be slab metadata and must be valid.
                unsafe { &*meta_slot }
            }
        }
    }
}

impl<const SLOT_SIZE: usize> Drop for SlabSlot<SLOT_SIZE> {
    fn drop(&mut self) {
        let head = self.find_slab_head();
        let SlabMeta::HeadFrame {
            free_list_head,
            nr_free_slots,
            ..
        } = head
        else {
            panic!("Invalid slab meta");
        };
        // Set the address of the current slot as the head after writing the
        // head to the slot.
        let addr = self.addr.as_ptr();
        free_list_head
            .fetch_update(Ordering::Release, Ordering::Acquire, |head| {
                unsafe {
                    *(addr as *mut usize) = head as usize;
                }
                Some(addr as *mut usize)
            })
            .unwrap();
        nr_free_slots.fetch_add(1, Ordering::Release);
    }
}

/// A list of slabs.
pub struct SlabList<const SLOT_SIZE: usize> {
    head: AtomicPtr<MetaSlot>,
}

impl<const SLOT_SIZE: usize> SlabList<SLOT_SIZE> {
    /// Creates a new empty slab cache.
    pub const fn new(size: usize) -> Self {
        Self {
            head: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Pushes a slab to the head of the list.
    pub fn push(&self, slab: Slab<SLOT_SIZE>) {
        self.head.fetch_update(Ordering::Release, Ordering::Acquire, |head| {
            let SlabMeta::HeadFrame { in_list, .. } = slab.0.meta(0) else {
                panic!("Invalid slab meta");
            };
            in_list.store(self as *const _ as *mut SlabList<SLOT_SIZE>, Ordering::Release);
            let head = self.head.load(Ordering::Acquire);
            let SlabMeta::HeadFrame { next_slab, .. } = slab.0.meta(0) else {
                panic!("Invalid slab meta");
            };
            next_slab.store(head as *const _ as *mut MetaSlot, Ordering::Release);
            Some(slab.0.head() as *mut MetaSlot)
        })
    }
}
