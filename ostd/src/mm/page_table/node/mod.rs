// SPDX-License-Identifier: MPL-2.0

//! This module defines page table node abstractions and the handle.
//!
//! The page table node is also frequently referred to as a page table in many architectural
//! documentations. It is essentially a page that contains page table entries (PTEs) that map
//! to child page tables nodes or mapped pages.
//!
//! This module leverages the page metadata to manage the page table pages, which makes it
//! easier to provide the following guarantees:
//!
//! The page table node is not freed when it is still in use by:
//!    - a parent page table node,
//!    - or a handle to a page table node,
//!    - or a processor.
//!
//! This is implemented by using a reference counter in the page metadata. If the above
//! conditions are not met, the page table node is ensured to be freed upon dropping the last
//! reference.
//!
//! One can acquire exclusive access to a page table node using merely the physical address of
//! the page table node. This is implemented by a lock in the page metadata. Here the
//! exclusiveness is only ensured for kernel code, and the processor's MMU is able to access the
//! page table node while a lock is held. So the modification to the PTEs should be done after
//! the initialization of the entity that the PTE points to. This is taken care in this module.
//!

mod child;
mod entry;
mod mcs;
mod rwlock;

use core::{
    cell::SyncUnsafeCell,
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
};

pub(in crate::mm) use self::{child::Child, entry::Entry};
use super::{nr_subpage_per_huge, PageTableEntryTrait};
use crate::{
    arch::mm::{PageTableEntry, PagingConsts},
    mm::{
        frame::{meta::AnyFrameMeta, Frame},
        paddr_to_vaddr,
        vm_space::Status,
        FrameAllocOptions, Infallible, Paddr, PagingConstsTrait, PagingLevel, VmReader,
    },
};

/// A smart pointer to a page table node.
///
/// This smart pointer is an owner of a page table node. Thus creating and
/// dropping it will affect the reference count of the page table node. If
/// dropped it as the last reference, the page table node and subsequent
/// children will be freed.
///
/// [`PageTableNode`] is read-only. To modify the page table node, lock and use
/// [`PageTableWriteLock`].
pub(super) type PageTableNode<E, C> = Frame<PageTablePageMeta<E, C>>;

impl<E: PageTableEntryTrait, C: PagingConstsTrait> PageTableNode<E, C> {
    /// Allocates a new empty page table node.
    ///
    /// This function returns an unlocked owning guard.
    pub(super) fn alloc(level: PagingLevel, is_tracked: MapTrackingStatus) -> Self {
        let meta = PageTablePageMeta::new(level, is_tracked);
        let frame = FrameAllocOptions::new()
            .zeroed(true)
            .alloc_frame_with(meta)
            .expect("Failed to allocate a page table node");
        // The allocated frame is zeroed. Make sure zero is absent PTE.
        debug_assert!(E::new_absent().as_bytes().iter().all(|&b| b == 0));

        frame
    }

    pub(super) fn alloc_marked(level: PagingLevel, status: Status) -> Self {
        let mut meta = PageTablePageMeta::new(level, MapTrackingStatus::Tracked);
        *meta.nr_children.get_mut() = nr_subpage_per_huge::<C>() as u16;

        let frame = FrameAllocOptions::new()
            .zeroed(false)
            .alloc_frame_with(meta)
            .expect("Failed to allocate a page table node");

        // Fill it with status.
        let frame_ptr = paddr_to_vaddr(frame.start_paddr()) as *mut E;
        let pte = E::new_status(status);
        for i in 0..nr_subpage_per_huge::<C>() {
            unsafe {
                frame_ptr.add(i).write(pte);
            };
        }

        frame
    }

    pub(super) fn level(&self) -> PagingLevel {
        self.meta().level
    }

    /// Gets to an accessible guard by pertaining the lock.
    ///
    /// This should be an unsafe function that requires the caller to ensure
    /// that preemption is disabled while the lock is held, or if the page is
    /// not shared with other CPUs.
    pub(super) fn lock_write(self) -> PageTableWriteLock<E, C> {
        self.meta().lock.lock_write();

        PageTableWriteLock::<E, C> { frame: Some(self) }
    }

    pub(super) fn lock_read(self) -> PageTableReadLock<E, C> {
        let g = self.meta().lock.lock_read();

        PageTableReadLock::<E, C> {
            frame: Some(self),
            bravo_guard: Some(g),
        }
    }

    /// Activates the page table assuming it is a root page table.
    ///
    /// Here we ensure not dropping an active page table by making a
    /// processor a page table owner. When activating a page table, the
    /// reference count of the last activated page table is decremented.
    /// And that of the current page table is incremented.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the page table to be activated has
    /// proper mappings for the kernel and has the correct const parameters
    /// matching the current CPU.
    ///
    /// # Panics
    ///
    /// Only top-level page tables can be activated using this function.
    pub(crate) unsafe fn activate(&self) {
        use crate::{
            arch::mm::{activate_page_table, current_page_table_paddr},
            mm::CachePolicy,
        };

        assert_eq!(self.level(), C::NR_LEVELS);

        let last_activated_paddr = current_page_table_paddr();
        if last_activated_paddr == self.start_paddr() {
            return;
        }

        activate_page_table(self.clone().into_raw(), CachePolicy::Writeback);

        // Restore and drop the last activated page table.
        // SAFETY: The physical address is valid and points to a forgotten page table node.
        drop(unsafe { Self::from_raw(last_activated_paddr) });
    }

    /// Activates the (root) page table assuming it is the first activation.
    ///
    /// It will not try dropping the last activate page table. It is the same
    /// with [`Self::activate()`] in other senses.
    pub(super) unsafe fn first_activate(&self) {
        use crate::{arch::mm::activate_page_table, mm::CachePolicy};

        activate_page_table(self.clone().into_raw(), CachePolicy::Writeback);
    }
}

/// A owned mutable guard that holds the read lock of a page table node.
///
/// This should be used as a linear type, i.e, it shouldn't be dropped. The
/// only way to destruct the type must be [`PageTableReadLock::unlock`].
#[derive(Debug)]
pub(super) struct PageTableReadLock<
    E: PageTableEntryTrait = PageTableEntry,
    C: PagingConstsTrait = PagingConsts,
> {
    // We need to wrap it in `Option` to perform the linear type check.
    frame: Option<Frame<PageTablePageMeta<E, C>>>,
    bravo_guard: Option<rwlock::bravo::BravoReadGuard>,
}

impl<E: PageTableEntryTrait, C: PagingConstsTrait> PageTableReadLock<E, C> {
    /// Gets the physical address of the page table node.
    pub(super) fn paddr(&self) -> Paddr {
        self.frame.as_ref().unwrap().start_paddr()
    }

    /// Gets the level of the page table node.
    pub(super) fn level(&self) -> PagingLevel {
        self.meta().level
    }

    /// Gets the tracking status of the page table node.
    pub(super) fn is_tracked(&self) -> MapTrackingStatus {
        self.meta().is_tracked
    }

    pub(super) fn read_child_ref(&self, idx: usize) -> Child<E, C> {
        let pte = self.read_pte(idx);
        // SAFETY: The provided `level` and `is_tracked` are the same as
        // the node containing the PTE.
        unsafe { Child::ref_from_pte(&pte, self.level(), self.is_tracked(), false) }
    }

    pub(super) fn unlock(mut self) -> PageTableNode<E, C> {
        let guard = self.bravo_guard.take().unwrap();
        self.meta().lock.unlock_read(guard);

        self.frame.take().unwrap()
    }

    fn read_pte(&self, idx: usize) -> E {
        assert!(idx < nr_subpage_per_huge::<C>());
        let ptr = paddr_to_vaddr(self.paddr()) as *mut E;
        // SAFETY:
        // - The page table node is alive. The index is inside the bound, so the page table entry is valid.
        unsafe { ptr.add(idx).read() }
    }

    fn meta(&self) -> &PageTablePageMeta<E, C> {
        self.frame.as_ref().unwrap().meta()
    }
}

impl<E: PageTableEntryTrait, C: PagingConstsTrait> Drop for PageTableReadLock<E, C> {
    fn drop(&mut self) {
        if self.frame.is_some() {
            panic!("Dropping `PageTableReadLock` instead of `unlock` it")
        }
    }
}

/// A owned mutable guard that holds the write lock of a page table node.
///
/// This should be used as a linear type, i.e, it shouldn't be dropped. The
/// only way to destruct the type must be [`PageTableWriteLock::unlock`].
#[derive(Debug)]
pub(super) struct PageTableWriteLock<
    E: PageTableEntryTrait = PageTableEntry,
    C: PagingConstsTrait = PagingConsts,
> {
    // We need to wrap it in `Option` to perform the linear type check.
    frame: Option<Frame<PageTablePageMeta<E, C>>>,
}

impl<E: PageTableEntryTrait, C: PagingConstsTrait> PageTableWriteLock<E, C> {
    /// Borrows an entry in the node at a given index.
    ///
    /// # Panics
    ///
    /// Panics if the index is not within the bound of
    /// [`nr_subpage_per_huge<C>`].
    pub(super) fn entry(&mut self, idx: usize) -> Entry<'_, E, C> {
        assert!(idx < nr_subpage_per_huge::<C>());
        // SAFETY: The index is within the bound.
        unsafe { Entry::new_at(self, idx) }
    }

    /// Gets the physical address of the page table node.
    pub(super) fn paddr(&self) -> Paddr {
        self.frame.as_ref().unwrap().start_paddr()
    }

    /// Gets the level of the page table node.
    pub(super) fn level(&self) -> PagingLevel {
        self.meta().level
    }

    /// Gets the tracking status of the page table node.
    pub(super) fn is_tracked(&self) -> MapTrackingStatus {
        self.meta().is_tracked
    }

    /// Unlocks the page table node.
    pub(super) fn unlock(mut self) -> PageTableNode<E, C> {
        self.meta().lock.unlock_write();

        self.frame.take().unwrap()
    }

    pub(super) fn start_paddr(&self) -> Paddr {
        self.frame.as_ref().unwrap().start_paddr()
    }

    /// Converts a raw physical address to a guard.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the physical address is valid and points to
    /// a forgotten page table node (see [`Self::into_raw_paddr`]) that is not
    /// yet restored.
    pub(super) unsafe fn from_raw_paddr(paddr: Paddr) -> Self {
        let frame = PageTableNode::from_raw(paddr);
        Self { frame: Some(frame) }
    }

    /// Gets the number of valid PTEs in the node.
    pub(super) fn nr_children(&self) -> u16 {
        // SAFETY: The lock is held so we have an exclusive access.
        unsafe { *self.meta().nr_children.get() }
    }

    /// Reads a non-owning PTE at the given index.
    ///
    /// A non-owning PTE means that it does not account for a reference count
    /// of the a page if the PTE points to a page. The original PTE still owns
    /// the child page.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the index is within the bound.
    unsafe fn read_pte(&self, idx: usize) -> E {
        debug_assert!(idx < nr_subpage_per_huge::<C>());
        let ptr = paddr_to_vaddr(self.paddr()) as *mut E;
        // SAFETY:
        // - The page table node is alive. The index is inside the bound, so the page table entry is valid.
        unsafe { ptr.add(idx).read() }
    }

    /// Writes a page table entry at a given index.
    ///
    /// This operation will leak the old child if the old PTE is present.
    ///
    /// The child represented by the given PTE will handover the ownership to
    /// the node. The PTE will be rendered invalid after this operation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    ///  1. The index must be within the bound;
    ///  2. The PTE must represent a child compatible with this page table node
    ///     (see [`Child::is_compatible`]).
    unsafe fn write_pte(&mut self, idx: usize, pte: E) {
        debug_assert!(idx < nr_subpage_per_huge::<C>());
        let ptr = paddr_to_vaddr(self.paddr()) as *mut E;
        // SAFETY:
        // - The page table node is alive. The index is inside the bound, so the page table entry is valid.
        unsafe { ptr.add(idx).write(pte) }
    }

    /// Gets the mutable reference to the number of valid PTEs in the node.
    fn nr_children_mut(&mut self) -> &mut u16 {
        // SAFETY: The lock is held so we have an exclusive access.
        unsafe { &mut *self.meta().nr_children.get() }
    }

    fn meta(&self) -> &PageTablePageMeta<E, C> {
        self.frame.as_ref().unwrap().meta()
    }
}

impl<E: PageTableEntryTrait, C: PagingConstsTrait> Drop for PageTableWriteLock<E, C> {
    fn drop(&mut self) {
        if self.frame.is_some() {
            panic!("Dropping `PageTableWriteLock` instead of `unlock` it")
        }
    }
}

/// An implicit access to the page table node.
///
/// Our lock protocol ensures that if write locking the covering node the node
/// can be mutably accessed.
///
/// This handle points to an actually unlocked page table node but you can
/// manipulate it.
#[derive(Debug)]
pub(super) struct PageTableImplicitWriteLock<E: PageTableEntryTrait, C: PagingConstsTrait>(
    ManuallyDrop<PageTableWriteLock<E, C>>,
);

impl<E: PageTableEntryTrait, C: PagingConstsTrait> PageTableImplicitWriteLock<E, C> {
    /// # Safety
    ///
    /// The `paddr` must point to a implicitly locked page table node.
    pub(super) unsafe fn from_raw_paddr(paddr: Paddr) -> Self {
        let write_lock = PageTableWriteLock::from_raw_paddr(paddr);
        Self(ManuallyDrop::new(write_lock))
    }
}

impl<E: PageTableEntryTrait, C: PagingConstsTrait> Deref for PageTableImplicitWriteLock<E, C> {
    type Target = PageTableWriteLock<E, C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<E: PageTableEntryTrait, C: PagingConstsTrait> DerefMut for PageTableImplicitWriteLock<E, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The metadata of any kinds of page table pages.
/// Make sure the the generic parameters don't effect the memory layout.
#[derive(Debug)]
pub(in crate::mm) struct PageTablePageMeta<
    E: PageTableEntryTrait = PageTableEntry,
    C: PagingConstsTrait = PagingConsts,
> {
    /// The readers-writer lock for the page table page.
    lock: rwlock::bravo::BravoSimpRwLock,
    /// The number of valid PTEs. It is mutable if the lock is held.
    pub nr_children: SyncUnsafeCell<u16>,
    /// The level of the page table page. A page table page cannot be
    /// referenced by page tables of different levels.
    pub level: PagingLevel,
    /// Whether the pages mapped by the node is tracked.
    pub is_tracked: MapTrackingStatus,
    _phantom: core::marker::PhantomData<(E, C)>,
}

/// Describe if the physical address recorded in this page table refers to a
/// page tracked by metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::mm) enum MapTrackingStatus {
    /// The page table node cannot contain references to any pages. It can only
    /// contain references to child page table nodes.
    NotApplicable,
    /// The mapped pages are not tracked by metadata. If any child page table
    /// nodes exist, they should also be tracked.
    Untracked,
    /// The mapped pages are tracked by metadata. If any child page table nodes
    /// exist, they should also be tracked.
    Tracked,
}

impl<E: PageTableEntryTrait, C: PagingConstsTrait> PageTablePageMeta<E, C> {
    pub fn new(level: PagingLevel, is_tracked: MapTrackingStatus) -> Self {
        Self {
            nr_children: SyncUnsafeCell::new(0),
            level,
            lock: rwlock::bravo::BravoSimpRwLock::new(),
            is_tracked,
            _phantom: PhantomData,
        }
    }
}

// SAFETY: We can read the page table node when we are here, regardless of
// whether the page table node is locked or not. If the page table is locked,
// it is trivial that we are safe.
//
// If the page table is not locked, we are the last owner of the PT and no
// other cursors can read it under the RCU read side critical section. Since
// We must be after the grace period to reach here.
unsafe impl<E: PageTableEntryTrait, C: PagingConstsTrait> AnyFrameMeta for PageTablePageMeta<E, C> {
    fn on_drop(&mut self, reader: &mut VmReader<Infallible>) {
        let nr_children = self.nr_children.get_mut();

        if *nr_children == 0 {
            return;
        }

        let level = self.level;
        let is_tracked = self.is_tracked;

        // Drop the children.
        while let Ok(pte) = reader.read_once::<E>() {
            // Here if we use directly `Child::from_pte` we would experience a
            // 50% increase in the overhead of the `drop` function. It seems that
            // Rust is very conservative about inlining and optimizing dead code
            // for `unsafe` code. So we manually inline the function here.
            if pte.is_present() {
                let paddr = pte.paddr();
                if !pte.is_last(level) {
                    // SAFETY: The PTE points to a page table node. The ownership
                    // of the child is transferred to the child then dropped.
                    drop(unsafe { Frame::<Self>::from_raw(paddr) });
                } else if is_tracked == MapTrackingStatus::Tracked {
                    // SAFETY: The PTE points to a tracked page. The ownership
                    // of the child is transferred to the child then dropped.
                    drop(unsafe { Frame::<dyn AnyFrameMeta>::from_raw(paddr) });
                }
            }
        }
    }
}
