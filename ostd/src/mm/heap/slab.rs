// SPDX-License-Identifier: MPL-2.0

//! Slabs for implementing the slab allocator.

use core::{alloc::AllocError, cell::UnsafeCell, ptr::NonNull};

use align_ext::AlignExt;

use super::slot::HeapSlot;
use crate::mm::{
    frame::{linked_list::Link, meta::AnyFrameMeta},
    paddr_to_vaddr, Frame, FrameAllocOptions, UniqueFrame, PAGE_SIZE,
};

/// A slab.
///
/// The slot size is the maximum size and alignment of the objects that can be
/// allocated from the slab. The slab is divided into slots of this size.
///
/// The size of the slot cannot be smaller than the size of [`usize`] and must
/// be a power of two. The size of the slab should be larger than the slot
/// size and [`PAGE_SIZE`].
pub type Slab<const SLOT_SIZE: usize> = UniqueFrame<Link<SlabMeta<SLOT_SIZE>>>;

/// A shared pointer to a slab.
///
/// It is solely useful to point to a slab from a stray slot. When an object of
/// this type exists no mutable references can be created to the slab. So don't
/// hold it for long.
pub type SharedSlab<const SLOT_SIZE: usize> = Frame<Link<SlabMeta<SLOT_SIZE>>>;

/// Frame metadata of a slab.
///
/// Each slab is backed by a [`UniqueFrame`].
#[derive(Debug)]
pub struct SlabMeta<const SLOT_SIZE: usize> {
    /// Points to the first free slot, or null if the slab is full.
    ///
    /// Only modifiable if a mutable reference to the slab is held.
    free_list_head: UnsafeCell<*mut usize>,

    /// The number of allocated slots.
    ///
    /// Only modifiable if a mutable reference to the slab is held.
    nr_allocated: UnsafeCell<u16>,
}

unsafe impl<const SLOT_SIZE: usize> Send for SlabMeta<SLOT_SIZE> {}
unsafe impl<const SLOT_SIZE: usize> Sync for SlabMeta<SLOT_SIZE> {}

unsafe impl<const SLOT_SIZE: usize> AnyFrameMeta for SlabMeta<SLOT_SIZE> {
    fn on_drop(&mut self, _reader: &mut crate::mm::VmReader<crate::mm::Infallible>) {
        let nr_allocated = *self.nr_allocated.get_mut();
        if nr_allocated != 0 {
            // FIXME: We have no mechanisms to forget the slab once we are here,
            // so we require the user to deallocate all slots before dropping.
            panic!("{} slots allocated when dropping a slab", nr_allocated);
        }
    }

    fn is_untyped(&self) -> bool {
        false
    }
}

impl<const SLOT_SIZE: usize> Slab<SLOT_SIZE> {
    /// Allocates a new slab of the given size.
    ///
    /// If the size is less than `SLOT_SIZE` or [`PAGE_SIZE`], the size will be
    /// the maximum of the two.
    pub fn new() -> crate::prelude::Result<Self> {
        // To ensure we can store a pointer in each slot.
        assert!(SLOT_SIZE >= core::mem::size_of::<usize>());
        debug_assert!(PAGE_SIZE / SLOT_SIZE <= u16::MAX as usize);

        let frame = FrameAllocOptions::new()
            .zeroed(false)
            .alloc_frame_with(Link::new(SlabMeta::<SLOT_SIZE> {
                free_list_head: UnsafeCell::new(core::ptr::null_mut()),
                nr_allocated: UnsafeCell::new(0),
            }))?;

        let head_paddr = frame.start_paddr();
        let head_vaddr = paddr_to_vaddr(head_paddr);

        // SAFETY: No one else can mutably access the newly allocated frame's
        // metadata.
        unsafe {
            frame
                .meta()
                .free_list_head
                .get()
                .write(head_vaddr as *mut usize)
        };

        // Initialize the free list as a linear list.
        // If a slot is free, the slot stores the address of the next free slot.
        for slot_offset in (0..PAGE_SIZE).step_by(SLOT_SIZE) {
            let slot_addr = head_vaddr + slot_offset;
            let next_slot_addr = if slot_offset + SLOT_SIZE >= PAGE_SIZE {
                core::ptr::null_mut::<usize>() as usize
            } else {
                slot_addr + SLOT_SIZE
            };
            let slot_ptr = slot_addr as *mut usize;
            // SAFETY: The virtual address is within the allocated frame.
            unsafe {
                *slot_ptr = next_slot_addr;
            }
        }

        Ok(frame.try_into().unwrap())
    }

    /// Gets the capacity of the slab (regardless of the number of allocated slots).
    pub const fn capacity(&self) -> u16 {
        (PAGE_SIZE / SLOT_SIZE) as u16
    }

    /// Gets the number of allocated slots.
    pub fn nr_allocated(&self) -> u16 {
        // SAFETY: We hold a reference to the slab.
        unsafe { *self.meta().nr_allocated.get() }
    }

    /// Allocates a slot from the slab.
    pub fn alloc(&mut self) -> Result<HeapSlot, AllocError> {
        let head_meta = self.meta();

        // SAFETY: We hold a mutable reference to the slab.
        let free_list_head_mut = unsafe { &mut *head_meta.free_list_head.get() };
        let nr_allocated_mut = unsafe { &mut *head_meta.nr_allocated.get() };

        // Set the head to the pointer stored in the current head slot and
        // return the current head.
        let Some(allocated) = NonNull::new(*free_list_head_mut as *mut u8) else {
            log::error!("Allocating a slot from a full slab");
            return Err(AllocError);
        };
        // SAFETY: If the head points to a slot, the slot must be free.
        let next = unsafe { **free_list_head_mut };
        *free_list_head_mut = next as *mut usize;
        *nr_allocated_mut += 1;

        Ok(HeapSlot::new(allocated, SLOT_SIZE))
    }

    /// Deallocates a slot to the slab.
    ///
    /// If the slot does not belong to the slab, it returns [`AllocError`].
    pub fn dealloc(&mut self, slot: HeapSlot) -> Result<(), AllocError> {
        if slot.paddr().align_down(PAGE_SIZE) != self.start_paddr() {
            log::error!("Deallocating a slot to a slab that does not own the slot");
            return Err(AllocError);
        }
        if SLOT_SIZE < slot.size() {
            log::error!("Deallocating a slot to a slab whose slot size mismatch");
            return Err(AllocError);
        }

        let head_meta = self.meta();

        // SAFETY: We hold a mutable reference to the slab.
        let free_list_head_mut = unsafe { &mut *head_meta.free_list_head.get() };
        let nr_allocated_mut = unsafe { &mut *head_meta.nr_allocated.get() };

        // Write the current head to the slot and set the head to the slot.
        let slot_ptr = slot.as_ptr() as *mut usize;

        // SAFETY: The slot must be writable.
        unsafe { slot_ptr.write(*free_list_head_mut as usize) };

        *free_list_head_mut = slot_ptr;
        *nr_allocated_mut -= 1;

        Ok(())
    }
}
