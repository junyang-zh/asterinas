// SPDX-License-Identifier: MPL-2.0

//! The page table cursor for mapping and querying over the page table.
//!
//! # The page table lock protocol
//!
//! We provide a fine-grained ranged mutual-exclusive lock protocol to allow
//! concurrent accesses to non-overlapping virtual ranges in the page table.
//!
//! [`CursorMut::new`] will lock a range in the virtual space and all the
//! operations on the range with the cursor will be atomic as a transaction.
//!
//! The guarantee of the lock protocol is that, if two cursors' ranges overlap,
//! all of one's operation must be finished before any of the other's
//! operation. The order depends on the scheduling of the threads. If a cursor
//! is ordered after another cursor, it will see all the changes made by the
//! previous cursor.
//!
//! The implementation of the lock protocol resembles two-phase locking (2PL).
//! [`CursorMut::new`] accepts an address range, which indicates the page table
//! entries that may be visited by this cursor. Then, [`CursorMut::new`] finds
//! an intermediate page table (not necessarily the last-level or the top-
//! level) which represents an address range that fully contains the whole
//! specified address range. Then it locks all the nodes in the sub-tree rooted
//! at the intermediate page table node, with a pre-order DFS order. The cursor
//! will only be able to access the page table entries in the locked range.
//! Upon destruction, the cursor will release the locks in the reverse order of
//! acquisition.

mod locking;

use core::{
    fmt::Debug,
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut, Range},
};

use align_ext::AlignExt;

use super::{
    PageTable, PageTableConfig, PageTableError, PageTableGuard, PagingConstsTrait, PagingLevel,
    PteState, PteStateRef, node::Entry as NodeEntry, page_size, pte_index,
};
use crate::{
    mm::{
        PageProperty, Vaddr,
        page_table::{PageTableNode, is_valid_range},
    },
    sync::RcuDrop,
    task::atomic_mode::InAtomicMode,
};

/// The cursor for traversal over the page table.
///
/// At any time, the cursor points to a page table entry in a certain level of
/// the page table hierarchy. And the entry have a corresponding virtual
/// address range, which covers the current virtual address of the cursor.
///
/// The current virtual address and level must be within the locked range of
/// the cursor.
#[derive(Debug)]
pub(crate) struct Cursor<'rcu, C: PageTableConfig> {
    /// The current path of the cursor.
    ///
    /// The level 1 page table lock guard is at index 0, and the level N page
    /// table lock guard is at index N - 1.
    path: [Option<PageTableGuard<'rcu, C>>; MAX_NR_LEVELS],
    /// The cursor should be used in a RCU read side critical section.
    rcu_guard: &'rcu dyn InAtomicMode,
    /// The level of the page table that the cursor currently points to.
    level: PagingLevel,
    /// The top-most level that the cursor is allowed to access.
    ///
    /// From `level` to `guard_level`, the nodes are held in `path`.
    guard_level: PagingLevel,
    /// The virtual address that the cursor currently points to.
    va: Vaddr,
    /// The virtual address range that is locked.
    barrier_va: Range<Vaddr>,
    _phantom: PhantomData<&'rcu PageTable<C>>,
}

/// The cursor of a page table that is capable of map, unmap or protect pages.
///
/// Mutable entry operations are exposed through [`Leaf`], [`Subtree`], and
/// [`VacantEntry`]. A virtual address range can only be accessed by one
/// cursor, regardless of the cursor's mutability.
#[derive(Debug)]
pub(crate) struct CursorMut<'rcu, C: PageTableConfig>(Cursor<'rcu, C>);

impl<'rcu, C: PageTableConfig> Deref for CursorMut<'rcu, C> {
    type Target = Cursor<'rcu, C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: PageTableConfig> DerefMut for CursorMut<'_, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The maximum value of `PagingConstsTrait::NR_LEVELS`.
const MAX_NR_LEVELS: usize = 4;

/// A fragment of a page table that can be taken out of the page table.
#[must_use]
#[derive(Debug)]
pub(crate) enum PageTableFrag<C: PageTableConfig> {
    /// A mapped page table item.
    Mapped { va: Vaddr, item: RcuDrop<C::Item> },
    /// A sub-tree of a page table that is taken out of the page table.
    ///
    /// The caller is responsible for dropping it after TLB coherence.
    StrayPageTable {
        pt: RcuDrop<PageTableNode<C>>,
        va: Vaddr,
        len: usize,
        num_frames: usize,
    },
}

/// The state of a queried page-table entry.
pub(crate) enum Entry<'cursor, 'rcu, C: PageTableConfig, T> {
    /// An entry that contains a mapping or points to a subtree.
    Value(T),
    /// An absent entry.
    Vacant(VacantEntry<'cursor, 'rcu, C>),
}

/// A cursor positioned at a mapped leaf entry.
pub(crate) struct Leaf<'cursor, 'rcu, C: PageTableConfig> {
    cursor: &'cursor mut CursorMut<'rcu, C>,
}

/// A cursor positioned at a mapping or a page-table subtree.
pub(crate) struct Subtree<'cursor, 'rcu, C: PageTableConfig> {
    cursor: &'cursor mut CursorMut<'rcu, C>,
}

/// A cursor positioned at an absent entry.
pub(crate) struct VacantEntry<'cursor, 'rcu, C: PageTableConfig> {
    cursor: &'cursor mut CursorMut<'rcu, C>,
}

impl<'rcu, C: PageTableConfig> Deref for Leaf<'_, 'rcu, C> {
    type Target = CursorMut<'rcu, C>;

    fn deref(&self) -> &Self::Target {
        self.cursor
    }
}

impl<'rcu, C: PageTableConfig> Deref for Subtree<'_, 'rcu, C> {
    type Target = CursorMut<'rcu, C>;

    fn deref(&self) -> &Self::Target {
        self.cursor
    }
}

impl<'rcu, C: PageTableConfig> Deref for VacantEntry<'_, 'rcu, C> {
    type Target = CursorMut<'rcu, C>;

    fn deref(&self) -> &Self::Target {
        self.cursor
    }
}

impl<'rcu, C: PageTableConfig> Cursor<'rcu, C> {
    /// Creates a cursor claiming exclusive access over the given range.
    ///
    /// The cursor will only be able to query the page table or jump within the
    /// given range.
    pub fn new(
        pt: &'rcu PageTable<C>,
        guard: &'rcu dyn InAtomicMode,
        va: &Range<Vaddr>,
    ) -> Result<Self, PageTableError> {
        if !is_valid_range::<C>(va) {
            return Err(PageTableError::InvalidVaddrRange(va.start, va.end));
        }
        if !va.start.is_multiple_of(C::BASE_PAGE_SIZE) || !va.end.is_multiple_of(C::BASE_PAGE_SIZE)
        {
            return Err(PageTableError::UnalignedVaddr);
        }

        const { assert!(C::NR_LEVELS as usize <= MAX_NR_LEVELS) };

        Ok(locking::lock_range(pt, guard, va))
    }

    /// Gets the current virtual address.
    pub fn virt_addr(&self) -> Vaddr {
        self.va
    }

    /// Gets the virtual address range that the current entry covers.
    pub fn cur_va_range(&self) -> Range<Vaddr> {
        let entry_size = page_size::<C>(self.level);
        let entry_start = self.va.align_down(entry_size);
        entry_start..entry_start + entry_size
    }

    /// Gets the current level of the cursor.
    pub fn level(&self) -> PagingLevel {
        self.level
    }

    /// Queries the mapping at the current virtual address.
    pub(in crate::mm) fn query(&self) -> PteStateRef<'rcu, C> {
        debug_assert!(self.barrier_va.contains(&self.va));
        self.path[self.level as usize - 1]
            .as_ref()
            .unwrap()
            .entry_state(pte_index::<C>(self.va, self.level))
    }

    /// Moves the cursor forward to the next mapped virtual address.
    ///
    /// If there is a mapped virtual address at or after the current address
    /// and before `end`, it will return that mapped address. In this case, the
    /// cursor will stop at the mapped address.
    ///
    /// Otherwise, it will return `None`. The cursor may stop at any address
    /// before `end`.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - `end` is before the current virtual address;
    ///  - `end` exceeds the cursor's range;
    ///  - `end` is not page-aligned.
    pub fn find_next(&mut self, end: Vaddr) -> Option<Vaddr> {
        self.find_next_impl(end, false)
    }

    /// Moves the cursor forward to the largest possible subtree that contains
    /// mapped pages.
    ///
    /// This is similar to [`Self::find_next`], except that the cursor will
    /// stop at the highest possible level, that the subtree's virtual address
    /// range is fully covered by the range ending at `end`. This is useful for
    /// [`CursorMut::unmap`].
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - `end` is before the current virtual address;
    ///  - `end` exceeds the cursor's range;
    ///  - `end` is not page-aligned.
    pub fn find_next_unmappable_subtree(&mut self, end: Vaddr) -> Option<Vaddr> {
        self.find_next_impl(end, true)
    }

    fn find_next_impl(&mut self, end: Vaddr, find_subtree: bool) -> Option<Vaddr> {
        assert_eq!(end % C::BASE_PAGE_SIZE, 0);
        assert!(end >= self.va, "end precedes current cursor position");
        assert!(end <= self.barrier_va.end, "end exceeds cursor range");

        let rcu_guard = self.rcu_guard;

        loop {
            while find_subtree && self.entry_at_level_fits_unmap(self.level + 1, end) {
                self.pop_level();
            }

            let cur_va = self.va;
            let cur_va_range = self.cur_va_range();
            let cur_entry_fits_range = self.entry_at_level_fits_unmap(self.level, end);

            match self.cur_entry().to_ref() {
                PteStateRef::PageTable(pt) => {
                    if find_subtree
                        && cur_entry_fits_range
                        && (C::TOP_LEVEL_CAN_UNMAP || self.level != C::NR_LEVELS)
                    {
                        return Some(cur_va);
                    }

                    // SAFETY: The `pt` must be locked and no other guards exist.
                    let pt_guard = unsafe { pt.make_guard_unchecked(rcu_guard) };
                    // If there's no mapped PTEs in the next level, we can
                    // skip to save time.
                    if pt_guard.nr_children() != 0 {
                        self.push_level(pt_guard);
                    } else {
                        let _ = ManuallyDrop::new(pt_guard);
                        if cur_va_range.end >= end {
                            return None;
                        } else {
                            self.move_forward();
                        }
                    }
                    continue;
                }
                PteStateRef::Absent => {
                    if cur_va_range.end >= end {
                        return None;
                    } else {
                        self.move_forward();
                    }
                    continue;
                }
                PteStateRef::Mapped(_) => {
                    return Some(cur_va);
                }
            }
        }
    }

    fn entry_at_level_fits_unmap(&self, level: PagingLevel, end: Vaddr) -> bool {
        if (level > self.guard_level) || (level == C::NR_LEVELS && !C::TOP_LEVEL_CAN_UNMAP) {
            return false;
        }
        let entry_size = page_size::<C>(level);
        let entry_start = self.va.align_down(entry_size);
        entry_start == self.va
            && entry_start
                .checked_add(entry_size)
                .is_some_and(|entry_end| entry_end <= end)
    }

    /// Jumps to the given virtual address.
    ///
    /// If the target address is out of the range, this method will return `Err`.
    ///
    /// If the target address is out of the range or if the address is not
    /// base-page-aligned, this method will return `Err`.
    pub fn jump(&mut self, va: Vaddr) -> Result<(), PageTableError> {
        if !va.is_multiple_of(C::BASE_PAGE_SIZE) || !self.barrier_va.contains(&va) {
            return Err(PageTableError::InvalidVaddr(va));
        }

        loop {
            let node_size = page_size::<C>(self.level + 1);
            let node_start = self.va.align_down(node_size);
            // If the address is within the current node, we can jump directly.
            // Note that `node_start + node_size` may overflow.
            if node_start <= va && va - node_start < node_size {
                self.va = va;
                return Ok(());
            }

            self.pop_level();
        }
    }

    /// Traverses forward to the end of [`Self::cur_va_range`].
    ///
    /// If reached the end of the current page table node, it (recursively)
    /// moves itself up to the next page of the parent page.
    fn move_forward(&mut self) {
        let next_va = self.cur_va_range().end;
        while self.level < self.guard_level && pte_index::<C>(next_va, self.level) == 0 {
            self.pop_level();
        }
        self.va = next_va;
    }

    /// Goes up a level.
    ///
    /// # Panics
    ///
    /// Panics if the cursor is already at the highest locked level (guard level).
    pub fn pop_level(&mut self) {
        assert!(self.level < self.guard_level);

        let taken = self.path[self.level as usize - 1]
            .take()
            .expect("popping a level without a lock");
        let _ = ManuallyDrop::new(taken);

        self.level += 1;
    }

    /// Goes down a level if a child page table exists.
    ///
    /// Returns the lower level if the cursor successfully goes down a level.
    pub fn push_level_if_exists(&mut self) -> Option<PagingLevel> {
        let cur_entry = self.cur_entry();
        match cur_entry.to_ref() {
            PteStateRef::PageTable(pt) => {
                // SAFETY: The `pt` must be locked and no other guards exist.
                let pt_guard = unsafe { pt.make_guard_unchecked(self.rcu_guard) };
                self.push_level(pt_guard);
                Some(self.level)
            }
            _ => None,
        }
    }

    /// Goes down a level to a child page table.
    fn push_level(&mut self, child_pt: PageTableGuard<'rcu, C>) {
        self.level -= 1;
        debug_assert_eq!(self.level, child_pt.level());

        let old = self.path[self.level as usize - 1].replace(child_pt);
        debug_assert!(old.is_none());
    }

    fn cur_entry(&mut self) -> NodeEntry<'_, 'rcu, C> {
        let node = self.path[self.level as usize - 1].as_mut().unwrap();
        node.entry(pte_index::<C>(self.va, self.level))
    }
}

impl<C: PageTableConfig> Drop for Cursor<'_, C> {
    fn drop(&mut self) {
        locking::unlock_range(self);
    }
}

impl<'rcu, C: PageTableConfig> CursorMut<'rcu, C> {
    /// Creates a cursor claiming exclusive access over the given range.
    ///
    /// The cursor will be able to query, jump, or modify the page table within
    /// the given range.
    pub fn new(
        pt: &'rcu PageTable<C>,
        guard: &'rcu dyn InAtomicMode,
        va: &Range<Vaddr>,
    ) -> Result<Self, PageTableError> {
        Ok(Self(Cursor::<'rcu, C>::new(pt, guard, va)?))
    }

    /// Queries the leaf entry at the current virtual address.
    pub fn query_leaf(&mut self) -> Entry<'_, 'rcu, C, Leaf<'_, 'rcu, C>> {
        loop {
            match self.0.query() {
                PteStateRef::PageTable(pt) => {
                    // SAFETY: The child page table is locked by this cursor.
                    let guard = unsafe { pt.make_guard_unchecked(self.0.rcu_guard) };
                    self.0.push_level(guard);
                }
                PteStateRef::Mapped(_) if self.entry_fits(self.0.barrier_va.end) => {
                    return Entry::Value(Leaf { cursor: self });
                }
                PteStateRef::Mapped(_) => {
                    let level = self
                        .0
                        .level
                        .checked_sub(1)
                        .expect("a base-page mapping cannot cross the cursor boundary");
                    self.adjust_level(level);
                }
                PteStateRef::Absent => {
                    return Entry::Vacant(VacantEntry { cursor: self });
                }
            }
        }
    }

    /// Queries the entry at `level`.
    ///
    /// This allocates missing intermediate page tables and splits larger
    /// mappings as needed to reach `level`.
    pub fn query_subtree(
        &mut self,
        level: PagingLevel,
    ) -> Entry<'_, 'rcu, C, Subtree<'_, 'rcu, C>> {
        assert!(1 <= level && level <= self.0.guard_level);
        self.adjust_level(level);

        match self.0.query() {
            PteStateRef::Absent => Entry::Vacant(VacantEntry { cursor: self }),
            PteStateRef::Mapped(_) | PteStateRef::PageTable(_) => {
                Entry::Value(Subtree { cursor: self })
            }
        }
    }

    /// Finds the next mapped leaf before `end`.
    pub fn find_leaf(&mut self, end: Vaddr) -> Option<Leaf<'_, 'rcu, C>> {
        loop {
            self.0.find_next(end)?;
            if self.entry_fits(end) {
                return Some(Leaf { cursor: self });
            }
            let level = self
                .0
                .level
                .checked_sub(1)
                .expect("a base-page mapping cannot cross the search boundary");
            self.adjust_level(level);
        }
    }

    /// Finds the next largest mapped subtree before `end`.
    pub fn find_subtree(&mut self, end: Vaddr) -> Option<Subtree<'_, 'rcu, C>> {
        self.0.find_next_unmappable_subtree(end)?;
        Some(Subtree { cursor: self })
    }

    fn entry_fits(&self, end: Vaddr) -> bool {
        let range = self.0.cur_va_range();
        range.start >= self.0.barrier_va.start && range.end <= end
    }

    /// Adjusts to the given level.
    ///
    /// When the specified level page table is not allocated, it will allocate
    /// and go to that page table. If the current virtual address contains a
    /// huge mapping, and the specified level is lower than the mapping, it
    /// will split the huge mapping into smaller mappings.
    ///
    /// # Panics
    ///
    /// Panics if the specified level is invalid.
    fn adjust_level(&mut self, to: PagingLevel) {
        let cursor = &mut self.0;
        assert!(1 <= to && to <= cursor.guard_level);

        let rcu_guard = cursor.rcu_guard;

        while cursor.level != to {
            if cursor.level < to {
                cursor.pop_level();
                continue;
            }
            // We are at a higher level, go down.
            let mut cur_entry = cursor.cur_entry();
            match cur_entry.to_ref() {
                PteStateRef::PageTable(pt) => {
                    // SAFETY: The `pt` must be locked and no other guards exist.
                    let pt_guard = unsafe { pt.make_guard_unchecked(rcu_guard) };
                    cursor.push_level(pt_guard);
                }
                PteStateRef::Absent => {
                    let child_guard = cur_entry.alloc_if_none(rcu_guard).unwrap();
                    cursor.push_level(child_guard);
                }
                PteStateRef::Mapped(_) => {
                    let split_child = cur_entry.split_if_mapped_huge(rcu_guard).unwrap();
                    cursor.push_level(split_child);
                }
            }
        }
    }

    /// Maps the item starting from the current address to a physical address range.
    ///
    /// The current virtual address should not be mapped.
    ///
    /// # Panics
    ///
    /// Panics if
    ///  - the cursor level does not match the level of the item to be mapped;
    ///  - the current virtual address is not aligned to the page size of the
    ///    item to be mapped;
    ///  - the end of the current virtual address range exceeds the locked range;
    ///  - the current virtual address range contains mappings.
    ///
    /// # Safety
    ///
    /// The caller should ensure that
    ///  - the range being mapped does not affect kernel's memory safety;
    ///  - the physical address to be mapped is valid and safe to use.
    unsafe fn map(&mut self, item: C::Item) {
        let cursor = &mut self.0;
        debug_assert!(cursor.va < cursor.barrier_va.end);

        let (_, level, _) = C::item_raw_info(&item);
        assert!(
            level <= C::HIGHEST_TRANSLATION_LEVEL,
            "cursor level not suitable for mapping"
        );
        assert_eq!(
            cursor.level, level,
            "cursor level do not match the item mapping level"
        );
        let size = page_size::<C>(level);
        assert_eq!(
            cursor.va % size,
            0,
            "cursor virtual address not aligned for mapping"
        );
        let end = cursor.va + size;
        assert!(
            end <= cursor.barrier_va.end,
            "cursor virtual address out-of-bound for mapping"
        );

        if !matches!(cursor.cur_entry().to_ref(), PteStateRef::Absent) {
            panic!("mapping over an already mapped page");
        }

        let _ = self.replace_cur_entry(PteState::Mapped(RcuDrop::new(item)));
    }

    /// Removes the page table fragment at the current PTE.
    ///
    /// The caller should handle TLB coherence if necessary, using the returned
    /// virtual address range.
    ///
    /// # Safety
    ///
    /// The caller should ensure that:
    ///  - the range being unmapped does not affect kernel's memory safety;
    ///  - there is no memory access to the unmapped range after dropping the
    ///    items in `PageTableFrag` but before flushing TLB entries that cache
    ///    the mappings.
    ///
    /// # Panics
    ///
    /// Panics if the current level is at the top level and the corresponding
    /// [`PageTableConfig::TOP_LEVEL_CAN_UNMAP`] is false.
    unsafe fn unmap(&mut self) -> Option<PageTableFrag<C>> {
        if !C::TOP_LEVEL_CAN_UNMAP && self.0.level == C::NR_LEVELS {
            panic!("unmapping top-level page table nodes");
        }
        assert!(
            self.entry_fits(self.0.barrier_va.end),
            "current page-table entry exceeds the locked range"
        );
        self.replace_cur_entry(PteState::Absent)
    }

    /// Applies the operation to the current PTE.
    ///
    /// It only modifies the page properties if the current entry state is
    /// [`PteState::Mapped`]. Otherwise, it does nothing.
    ///
    /// # Safety
    ///
    /// The caller should ensure that:
    ///  - the range being protected with the operation does not affect
    ///    kernel's memory safety;
    ///  - the privileged flag `AVAIL1` should not be altered, since this flag
    ///    is reserved for all page tables.
    unsafe fn protect(&mut self, op: &mut impl FnMut(&mut PageProperty)) {
        assert!(
            self.entry_fits(self.0.barrier_va.end),
            "current page-table entry exceeds the locked range"
        );
        self.0.cur_entry().protect(op);
    }

    fn replace_cur_entry(&mut self, new_child: PteState<C>) -> Option<PageTableFrag<C>> {
        let cursor = &mut self.0;
        let rcu_guard = cursor.rcu_guard;

        let va = cursor.va;
        let level = cursor.level;

        let old = cursor.cur_entry().replace(new_child);
        match old {
            PteState::Absent => None,
            PteState::Mapped(item) => Some(PageTableFrag::Mapped { va, item }),
            PteState::PageTable(pt) => {
                debug_assert_eq!(pt.level(), level - 1);

                if !C::TOP_LEVEL_CAN_UNMAP && level == C::NR_LEVELS {
                    let _ = ManuallyDrop::new(pt); // leak it to make shared PTs stay `'static`.
                    panic!("unmapping shared kernel page table nodes");
                }

                // SAFETY: We must have locked this node.
                let locked_pt = unsafe { pt.borrow().make_guard_unchecked(rcu_guard) };
                // SAFETY:
                //  - We checked that we are not unmapping shared kernel page table nodes.
                //  - We must have locked the entire sub-tree since the range is locked.
                let num_frames =
                    unsafe { locking::dfs_mark_stray_and_unlock(rcu_guard, locked_pt) };

                Some(PageTableFrag::StrayPageTable {
                    pt,
                    va,
                    len: page_size::<C>(cursor.level),
                    num_frames,
                })
            }
        }
    }
}

#[cfg_attr(not(ktest), expect(dead_code))]
impl<'cursor, 'rcu, C: PageTableConfig> Leaf<'cursor, 'rcu, C> {
    /// Gets the mapped item.
    pub fn item(&self) -> C::ItemRef<'rcu> {
        let PteStateRef::Mapped(item) = self.cursor.0.query() else {
            unreachable!("a leaf entry must remain mapped");
        };
        item
    }

    /// Applies a protection operation to the mapped item.
    ///
    /// # Safety
    ///
    /// The caller must uphold the safety requirements of [`CursorMut::protect`].
    pub unsafe fn protect(self, op: &mut impl FnMut(&mut PageProperty)) -> Self {
        // SAFETY: The caller upholds the requirements.
        unsafe { self.cursor.protect(op) };
        self
    }

    /// Removes the mapped item.
    ///
    /// # Safety
    ///
    /// The caller must uphold the safety requirements of [`CursorMut::unmap`].
    pub unsafe fn unmap(self) -> (VacantEntry<'cursor, 'rcu, C>, PageTableFrag<C>) {
        let frag = unsafe { self.cursor.unmap() }.expect("a leaf entry must remain mapped");
        (
            VacantEntry {
                cursor: self.cursor,
            },
            frag,
        )
    }

    /// Moves to the next entry at the same paging level.
    pub fn next(self) -> Option<Entry<'cursor, 'rcu, C, Subtree<'cursor, 'rcu, C>>> {
        next_entry(self.cursor)
    }
}

#[cfg_attr(not(ktest), expect(dead_code))]
impl<'cursor, 'rcu, C: PageTableConfig> Subtree<'cursor, 'rcu, C> {
    /// Gets the mapped item, or `None` if this entry points to a subtree.
    pub fn item(&self) -> Option<C::ItemRef<'rcu>> {
        match self.cursor.0.query() {
            PteStateRef::Mapped(item) => Some(item),
            PteStateRef::PageTable(_) => None,
            PteStateRef::Absent => unreachable!("a subtree entry cannot be vacant"),
        }
    }

    /// Resolves this entry to a mapped leaf or a vacancy.
    pub fn query_leaf(self) -> Entry<'cursor, 'rcu, C, Leaf<'cursor, 'rcu, C>> {
        self.cursor.query_leaf()
    }

    /// Removes the mapping or subtree.
    ///
    /// # Safety
    ///
    /// The caller must uphold the safety requirements of [`CursorMut::unmap`].
    pub unsafe fn unmap(self) -> (VacantEntry<'cursor, 'rcu, C>, PageTableFrag<C>) {
        let frag = unsafe { self.cursor.unmap() }.expect("a subtree entry must remain present");
        (
            VacantEntry {
                cursor: self.cursor,
            },
            frag,
        )
    }

    /// Moves to the next entry at the same paging level.
    pub fn next(self) -> Option<Entry<'cursor, 'rcu, C, Subtree<'cursor, 'rcu, C>>> {
        next_entry(self.cursor)
    }
}

#[cfg_attr(not(ktest), expect(dead_code))]
impl<'cursor, 'rcu, C: PageTableConfig> VacantEntry<'cursor, 'rcu, C> {
    /// Maps an item into this vacant entry.
    ///
    /// # Safety
    ///
    /// The caller must uphold the safety requirements of [`CursorMut::map`].
    pub unsafe fn map(self, item: C::Item) -> Leaf<'cursor, 'rcu, C> {
        let (_, level, _) = C::item_raw_info(&item);
        self.cursor.adjust_level(level);
        debug_assert!(matches!(self.cursor.0.query(), PteStateRef::Absent));
        // SAFETY: The caller upholds the requirements.
        unsafe { self.cursor.map(item) };
        Leaf {
            cursor: self.cursor,
        }
    }

    /// Moves to the next entry at the same paging level.
    pub fn next(self) -> Option<Entry<'cursor, 'rcu, C, Subtree<'cursor, 'rcu, C>>> {
        next_entry(self.cursor)
    }
}

#[cfg_attr(not(ktest), expect(dead_code))]
fn next_entry<'cursor, 'rcu, C: PageTableConfig>(
    cursor: &'cursor mut CursorMut<'rcu, C>,
) -> Option<Entry<'cursor, 'rcu, C, Subtree<'cursor, 'rcu, C>>> {
    let level = cursor.level();
    if cursor.cur_va_range().end >= cursor.0.barrier_va.end {
        return None;
    }

    cursor.0.move_forward();
    Some(cursor.query_subtree(level))
}
