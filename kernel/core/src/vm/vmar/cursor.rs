// SPDX-License-Identifier: MPL-2.0

//! Kernel-side helpers for VM-space cursor operations.

use core::ops::Range;

use align_ext::AlignExt;
use ostd::mm::{
    Vaddr, page_size_at,
    vm_space::{Cursor, CursorMut, VmQueriedItem},
};

use super::vmar_impls::{PerPtMeta, PteRangeMeta, VmarCursorMut};
use crate::vm::vmar::{
    interval_set::Interval,
    util::get_intersected_range,
    vm_mapping::{MappedMemory, VmMapping},
    vmar_impls::RsAsDelta,
};

pub(super) trait CursorExt {
    /// Moves the cursor to the leaf page table entry at the current virtual address.
    fn to_leaf(&mut self) -> &mut Self;

    /// Finds the first mapped [`VmMapping`] before `end`.
    ///
    /// The cursor's virtual address is monotonically increasing and the cursor
    /// is left at the level of the returned mapping. Its virtual address may
    /// lie inside, rather than at the start of, that mapping.
    fn find_next_mapped(&mut self, end: Vaddr) -> Option<&VmMapping>;

    /// Finds the first mapped [`VmMapping`] before `end` and projects an owned result.
    ///
    /// Cursor positioning is the same as [`Self::find_next_mapped`]. The callback
    /// runs once on a hit and never on a miss; its result cannot borrow the mapping.
    fn find_next_mapped_with<T>(
        &mut self,
        end: Vaddr,
        project: impl FnOnce(&VmMapping) -> T,
    ) -> Option<T>;
}

enum NextMappedStep {
    End,
    PopLevel,
    PushLevel(Range<Vaddr>),
}

macro_rules! impl_cursor_ext {
    ($cursor:ty) => {
        impl CursorExt for $cursor {
            fn to_leaf(&mut self) -> &mut Self {
                while self.push_level_if_exists().is_some() {}
                self
            }

            fn find_next_mapped(&mut self, end: Vaddr) -> Option<&VmMapping> {
                self.find_next_mapped_with(end, |_| ())?;
                let Some(PteRangeMeta::VmMapping(mapping)) =
                    self.aux_meta().inner.find_next(&self.virt_addr())
                else {
                    unreachable!();
                };
                Some(mapping)
            }

            fn find_next_mapped_with<T>(
                &mut self,
                end: Vaddr,
                project: impl FnOnce(&VmMapping) -> T,
            ) -> Option<T> {
                let mut exhausted_child: Option<*const PerPtMeta> = None;
                loop {
                    let cur_va = self.virt_addr();
                    if cur_va >= end {
                        return None;
                    }

                    let step = match self.aux_meta().inner.find_next(&cur_va) {
                        None if self.level() == self.guard_level() => NextMappedStep::End,
                        None => NextMappedStep::PopLevel,
                        Some(meta) if meta.range().start >= end => NextMappedStep::End,
                        Some(PteRangeMeta::ChildPt(range)) => {
                            NextMappedStep::PushLevel(range.clone())
                        }
                        Some(PteRangeMeta::VmMapping(mapping)) => {
                            return Some(project(mapping));
                        }
                    };

                    match step {
                        NextMappedStep::End => return None,
                        NextMappedStep::PopLevel => {
                            exhausted_child = Some(self.aux_meta() as *const PerPtMeta);
                            self.pop_level();
                        }
                        NextMappedStep::PushLevel(range) => {
                            if cur_va < range.start {
                                self.jump(range.start).unwrap();
                            }
                            self.push_level_if_exists().unwrap();
                            if exhausted_child
                                .take()
                                .is_some_and(|child| core::ptr::eq(child, self.aux_meta()))
                            {
                                // We popped from this child because there was no more
                                // metadata in it. Do not immediately re-enter it; move
                                // to the next parent entry instead. A different child
                                // can start at the same boundary and must still be
                                // visited.
                                self.pop_level();
                                if range.end >= end || self.jump(range.end).is_err() {
                                    return None;
                                }
                            }
                        }
                    }
                }
            }
        }
    };
}

impl_cursor_ext!(Cursor<'_, PerPtMeta>);
impl_cursor_ext!(CursorMut<'_, PerPtMeta>);

pub(super) trait CursorMutExt {
    /// Splits the current mapping until its virtual address range is contained in `range`.
    fn split_if_map_exceeds_range(&mut self, range: &Range<Vaddr>);
}

impl CursorMutExt for VmarCursorMut<'_> {
    fn split_if_map_exceeds_range(&mut self, range: &Range<Vaddr>) {
        while self.cur_va_range().start < range.start || self.cur_va_range().end > range.end {
            self.adjust_level(self.level() - 1);
        }
    }
}

/// Finds and takes the next unmappable auxiliary metadata in the given range.
///
/// If there's any metadata that overlaps the given range, it splits and takes
/// the overlapping part and returns it. The cursor's virtual address will be
/// at the start of the taken metadata.
pub(super) fn take_next_unmappable(
    cursor: &mut VmarCursorMut<'_>,
    end: Vaddr,
) -> Option<PteRangeMeta> {
    let start = cursor.virt_addr();
    let mut exhausted_child: Option<*const PerPtMeta> = None;
    while cursor.virt_addr() < end {
        let cur_va = cursor.virt_addr();
        let Some(ref meta) = cursor.aux_meta_mut().inner.find_next(&cur_va) else {
            if cursor.level() == cursor.guard_level() {
                return None;
            } else {
                exhausted_child = Some(cursor.aux_meta() as *const PerPtMeta);
                cursor.pop_level();
                continue;
            }
        };
        if meta.range().start >= end {
            return None;
        }
        match meta {
            PteRangeMeta::ChildPt(r) => {
                let range = r.clone();
                cursor.jump(range.start.max(start)).unwrap();
                if let Some(child) = exhausted_child.take() {
                    cursor.push_level_if_exists().unwrap();
                    let is_exhausted_child = core::ptr::eq(child, cursor.aux_meta());
                    cursor.pop_level();
                    if is_exhausted_child {
                        if range.end >= end || cursor.jump(range.end).is_err() {
                            break;
                        }
                        continue;
                    }
                }
                if start <= range.start && range.end <= end {
                    return cursor.aux_meta_mut().inner.take_one(&range.start);
                } else {
                    cursor.push_level_if_exists().unwrap();
                    continue;
                }
            }
            PteRangeMeta::VmMapping(vm_mapping) => {
                let range = vm_mapping.range();
                cursor.jump(range.start.max(start)).unwrap();
                if start <= range.start && range.end <= end {
                    let taken = cursor
                        .aux_meta_mut()
                        .inner
                        .take_one(&range.start)
                        .unwrap()
                        .unwrap_mapping();
                    return Some(PteRangeMeta::VmMapping(taken));
                } else {
                    let intersected_range = get_intersected_range(&(start..end), &range);
                    propagate_if_needed(cursor, intersected_range.len());

                    let vm_mapping = cursor
                        .aux_meta_mut()
                        .inner
                        .take_one(&intersected_range.start)
                        .unwrap()
                        .unwrap_mapping();

                    let taken = split_and_insert_rest(cursor, vm_mapping, intersected_range);
                    return Some(PteRangeMeta::VmMapping(taken));
                }
            }
        }
    }

    None
}

/// Count all the mapped pages in the subtree and update the RSS & AS as if
/// doing unmapping.
///
/// The cursor must be at a PTE pointing to a child page table.
///
/// Returns the total number of mapped base pages, including I/O pages, for
/// comparison with the page-table cursor's unmap count.
pub(super) fn unmap_count_rs_as(
    cursor: &mut VmarCursorMut<'_>,
    end: Vaddr,
    rs_as_delta: &mut RsAsDelta,
) -> usize {
    let old_va = cursor.virt_addr();
    let old_level = cursor.level();

    let mut total_frames_unmapped = 0;

    while let Some((vm_mapping_range, frames_mapped, rss_type, is_device)) = cursor
        .find_next_mapped_with(end, |mapping| {
            (
                mapping.range(),
                mapping.frames_mapped(),
                mapping.rss_type(),
                matches!(mapping.mapped_mem(), MappedMemory::Device(_)),
            )
        })
    {
        // Device mappings can contain both RAM and I/O pages. I/O pages count
        // towards the cursor's unmap result, but must not affect RSS or the
        // cached number of RAM frames.
        let mut count_pages = || {
            let mut ram_frames = 0;
            let mut io_pages = 0;
            let cur_page_size = page_size_at(cursor.level());
            for va in vm_mapping_range.clone().step_by(cur_page_size) {
                cursor.jump(va).unwrap();
                match cursor.query() {
                    VmQueriedItem::MappedRam { .. } => ram_frames += 1,
                    VmQueriedItem::MappedIoMem { .. } => {
                        io_pages += cur_page_size / page_size_at(1);
                    }
                    VmQueriedItem::PageTable => {
                        panic!("found page table under VM mapping at {:#x}", va);
                    }
                    VmQueriedItem::None => {}
                }
            }
            if let Some(frames_mapped) = frames_mapped {
                debug_assert_eq!(frames_mapped, ram_frames);
            }
            (ram_frames, io_pages)
        };
        let (ram_frames, io_pages) = match frames_mapped {
            Some(frames) if !is_device && !cfg!(debug_assertions) => (frames, 0),
            _ => count_pages(),
        };

        rs_as_delta.add_rs(rss_type, -(ram_frames as isize));
        rs_as_delta.sub_as(vm_mapping_range.len());

        total_frames_unmapped += ram_frames + io_pages;

        // The subtree's page-table frames are reclaimed asynchronously, but
        // mapping-owned files must be closed as part of this unmap operation.
        cursor
            .aux_meta_mut()
            .inner
            .take_one(&vm_mapping_range.start);

        if cursor.jump(vm_mapping_range.end).is_err() {
            break;
        }
    }

    cursor.jump(old_va).unwrap();
    cursor.adjust_level(old_level);

    total_frames_unmapped
}

/// Propagates the huge [`VmMapping`] and the PTE at the current VA if
///  - the start is not aligned, or
///  - the end is inside the PTE's range.
pub(super) fn propagate_if_needed(cursor: &mut VmarCursorMut<'_>, len: usize) {
    let start = cursor.virt_addr();
    let end = start + len;

    cursor.split_if_map_exceeds_range(&(start..end));
}

/// Splits the `split` range part from the given [`VmMapping`] and puts the
/// rest back to current PT's auxiliary metadata.
///
/// This function assumes that
///  1. the provided [`VmMapping`] is taken from current PT's auxiliary
///     metadata, so no merging is needed when inserting back the rest parts;
///  2. [`propagate_if_needed`] has been called before, so that the start of
///     `split` is aligned to the current level's page size.
///
/// And if the end is not aligned, this function only extracts the aligned part.
pub(super) fn split_and_insert_rest(
    cursor: &mut VmarCursorMut<'_>,
    vm_mapping: VmMapping,
    split: Range<Vaddr>,
) -> VmMapping {
    let cur_page_size = page_size_at(cursor.level());

    debug_assert!(split.start.is_multiple_of(cur_page_size));

    let aligned_range = split.start..split.end.align_down(cur_page_size);

    debug_assert!(!aligned_range.is_empty());

    let (left, taken, right) = vm_mapping.split_range(&aligned_range);

    if let Some(left) = left {
        cursor.aux_meta_mut().insert_without_try_merge(left);
    }
    if let Some(right) = right {
        cursor.aux_meta_mut().insert_without_try_merge(right);
    }

    taken
}

/// Checks whether the given range is fully mapped.
///
/// If fully mapped, returns the reference to the last mapping (split at page
/// table boundaries).
///
/// # Why a Macro?
///
/// It could be a function with the following signature:
///
/// ```ignore
/// pub(super) fn check_range_mapped(
//     cursor: &mut VmarCursorMut<'_>,
///     end: Vaddr,
/// ) -> Result<&VmMapping>;
/// ```
///
/// But the borrow checker is unreasonably unhappy. Using a macro magically
/// avoids this issue.
macro_rules! check_range_mapped {
    ($cursor:expr, $end:expr) => {{
        use $crate::{
            error::{Errno, Error},
            prelude::*,
            vm::vmar::{VmMapping, cursor::CursorExt},
        };

        const ERR: Result<&VmMapping> = Err(Error::with_message(
            Errno::EFAULT,
            "the range is not fully mapped",
        ));
        let start = $cursor.virt_addr();

        let mut last_end = None;

        loop {
            let Some(vm_mapping) = $cursor.find_next_mapped($end) else {
                break ERR;
            };

            if let Some(last_end) = last_end
                && last_end != vm_mapping.map_to_addr()
            {
                debug_assert!(last_end < vm_mapping.map_to_addr());
                break ERR;
            } else if last_end.is_none() && vm_mapping.map_to_addr() > start {
                break ERR;
            }

            let map_end = vm_mapping.map_end();
            if map_end >= $end {
                break Ok(vm_mapping);
            }

            last_end = Some(map_end);
            $cursor.jump(map_end).unwrap();
        }
    }};
}

pub(super) use check_range_mapped;

/// Checks whether the given range is fully mapped.
///
/// If fully mapped within one [`VmMapping`], returns the start address of the
/// last mapping (split at page table boundaries).
///
/// # Why a Macro?
///
/// It could be a function with the following signature:
///
/// ```ignore
/// pub(super) fn check_range_within_one_mapping(
///     cursor: &mut VmarCursorMut<'_>,
///     end: Vaddr,
/// ) -> Result<&VmMapping>;
/// ```
///
/// But the borrow checker is unreasonably unhappy. Using a macro magically
/// avoids this issue.
macro_rules! check_range_within_one_mapping {
    ($cursor:expr, $end:expr) => {{
        use $crate::{
            error::{Errno, Error},
            prelude::*,
            vm::vmar::{VmMapping, cursor::CursorExt},
        };

        const ERR: Result<&VmMapping> = Err(Error::with_message(
            Errno::EFAULT,
            "the range is not covered by a single mapping",
        ));
        let start = $cursor.virt_addr();

        let mut last: Option<VmMapping> = None;

        loop {
            let Some(vm_mapping) = $cursor.find_next_mapped($end) else {
                break ERR;
            };

            if let Some(last) = last {
                if !last.can_merge_with(vm_mapping) {
                    break ERR;
                }
            } else if vm_mapping.map_to_addr() > start {
                break ERR;
            }

            let map_end = vm_mapping.map_end();
            if map_end >= $end {
                break Ok(vm_mapping);
            }

            last = Some(vm_mapping.clone_for_check());
            $cursor.jump(map_end).unwrap();
        }
    }};
}

pub(super) use check_range_within_one_mapping;

/// #Panics
///
/// Panics if the range contains [`VmMapping`] or mapped pages.
#[cfg(any(debug_assertions, ktest))]
pub(super) fn check_range_not_mapped(cursor: &mut VmarCursorMut, range: Range<Vaddr>) {
    cursor.jump(range.start).unwrap();
    if let Some(mapped_range) = cursor.find_next_mapped_with(range.end, |mapping| mapping.range()) {
        panic!(
            "existing VM mapping found in range {:#x?} to clear: {:#x?}",
            range, mapped_range
        );
    }
    cursor.jump(range.start).unwrap();
    if let Some(va) = cursor.find_next(range.end) {
        panic!(
            "existing page table mapping found in range {:#x?} to clear: {:#x?}",
            range, va
        );
    }
}

#[cfg(ktest)]
mod projection_tests {
    use alloc::boxed::Box;
    use core::{cell::Cell, num::NonZeroUsize};

    use ostd::{
        mm::{HIGHEST_PAGING_LEVEL, PagingLevel, vm_space::VmSpace},
        prelude::ktest,
        task::disable_preempt,
    };

    use super::*;
    use crate::vm::{perms::VmPerms, vmar::MmapMode};

    // Cover two root entries so both cursor constructors retain the root guard.
    // This reserves no resident user pages and avoids constructor-driven descent.
    fn root_range() -> Range<Vaddr> {
        0..2 * page_size_at(HIGHEST_PAGING_LEVEL)
    }

    fn insert_mapping(space: &VmSpace<PerPtMeta>, range: Range<Vaddr>, owner: PagingLevel) {
        let guard = disable_preempt();
        let mut cursor = space.cursor_mut(&guard, &root_range()).unwrap();
        assert_eq!(cursor.guard_level(), HIGHEST_PAGING_LEVEL);
        cursor.jump(range.start).unwrap();
        cursor.adjust_level(owner);
        cursor
            .aux_meta_mut()
            .insert_without_try_merge(VmMapping::new(
                NonZeroUsize::new(range.len()).unwrap(),
                range.start,
                MappedMemory::Anonymous,
                None,
                MmapMode::Private,
                false,
                VmPerms::READ,
            ));
    }

    fn allocate_child(space: &VmSpace<PerPtMeta>, va: Vaddr) {
        let guard = disable_preempt();
        let mut cursor = space.cursor_mut(&guard, &root_range()).unwrap();
        cursor.jump(va).unwrap();
        cursor.adjust_level(1);
    }

    // Each call checks four independent cursor acquisitions. Never hold two
    // overlapping cursors simultaneously: even immutable cursors lock the tree.
    // Expected values and positions are explicit, in addition to API agreement.
    fn check_case(
        space: &VmSpace<PerPtMeta>,
        start: Vaddr,
        end: Vaddr,
        initial_level: PagingLevel,
        expected: Option<Range<Vaddr>>,
        final_state: (Vaddr, PagingLevel),
    ) {
        macro_rules! check_cursor_kind {
            ($constructor:ident) => {
                for reference_api in [false, true] {
                    // Returning this Box moves it out of the closure, requiring
                    // FnOnce rather than merely accepting a Copy/Fn capture.
                    let owned = Box::new(0xa5usize);
                    let calls = Cell::new(0);
                    let guard = disable_preempt();
                    let mut cursor = space.$constructor(&guard, &root_range()).unwrap();
                    assert_eq!(cursor.guard_level(), HIGHEST_PAGING_LEVEL);
                    cursor.jump(start).unwrap();
                    while cursor.level() > initial_level {
                        cursor.push_level_if_exists().unwrap();
                    }
                    assert_eq!(cursor.level(), initial_level);
                    let actual = if reference_api {
                        cursor.find_next_mapped(end).map(|mapping| {
                            assert_eq!(mapping.perms(), VmPerms::READ);
                            assert_eq!(mapping.frames_mapped(), Some(0));
                            mapping.range()
                        })
                    } else {
                        let calls_ref = &calls;
                        let projected = cursor.find_next_mapped_with(end, move |mapping| {
                            calls_ref.set(calls_ref.get() + 1);
                            assert_eq!(mapping.perms(), VmPerms::READ);
                            assert_eq!(mapping.frames_mapped(), Some(0));
                            (mapping.range(), owned)
                        });
                        assert_eq!(calls.get(), usize::from(expected.is_some()));
                        projected.map(|(range, token)| {
                            assert_eq!(*token, 0xa5);
                            range
                        })
                    };
                    assert_eq!(actual, expected);
                    assert_eq!((cursor.virt_addr(), cursor.level()), final_state);
                }
            };
        }
        check_cursor_kind!(cursor);
        check_cursor_kind!(cursor_mut);
    }

    #[ktest]
    fn aux_projection_empty_root() {
        let space = VmSpace::<PerPtMeta>::new();
        let p = page_size_at(1);
        check_case(
            &space,
            p,
            8 * p,
            HIGHEST_PAGING_LEVEL,
            None,
            (p, HIGHEST_PAGING_LEVEL),
        );
        check_case(
            &space,
            p,
            p,
            HIGHEST_PAGING_LEVEL,
            None,
            (p, HIGHEST_PAGING_LEVEL),
        );
    }

    #[ktest]
    fn aux_projection_start_interior_gap_and_exact_end() {
        let space = VmSpace::<PerPtMeta>::new();
        let p = page_size_at(1);
        let mapping = 4 * p..8 * p;
        insert_mapping(&space, mapping.clone(), HIGHEST_PAGING_LEVEL);
        for start in [p, mapping.start, mapping.start + p] {
            // Finding metadata after a same-owner gap does not move the cursor
            // to mapping.start. Preserve this existing API behavior explicitly.
            check_case(
                &space,
                start,
                mapping.end,
                HIGHEST_PAGING_LEVEL,
                Some(mapping.clone()),
                (start, HIGHEST_PAGING_LEVEL),
            );
        }
        check_case(
            &space,
            mapping.end,
            9 * p,
            HIGHEST_PAGING_LEVEL,
            None,
            (mapping.end, HIGHEST_PAGING_LEVEL),
        );
        check_case(
            &space,
            mapping.start,
            mapping.start,
            HIGHEST_PAGING_LEVEL,
            None,
            (mapping.start, HIGHEST_PAGING_LEVEL),
        );
    }

    #[ktest]
    fn aux_projection_each_mapping_owner_level() {
        let p = page_size_at(1);
        for owner in 1..=HIGHEST_PAGING_LEVEL {
            let space = VmSpace::<PerPtMeta>::new();
            let mapping = 4 * p..8 * p;
            insert_mapping(&space, mapping.clone(), owner);
            for start in [p, mapping.start, mapping.start + p] {
                check_case(
                    &space,
                    start,
                    mapping.end,
                    HIGHEST_PAGING_LEVEL,
                    Some(mapping.clone()),
                    (start, owner),
                );
            }
            // Also begin already descended to the mapping's owning table.
            check_case(&space, 5 * p, 8 * p, owner, Some(mapping), (5 * p, owner));
        }
    }

    #[ktest]
    fn aux_projection_end_excludes_next_mapping() {
        let p = page_size_at(1);
        let space = VmSpace::<PerPtMeta>::new();
        insert_mapping(&space, 4 * p..8 * p, HIGHEST_PAGING_LEVEL);
        for end in [3 * p, 4 * p] {
            check_case(
                &space,
                p,
                end,
                HIGHEST_PAGING_LEVEL,
                None,
                (p, HIGHEST_PAGING_LEVEL),
            );
        }
        let child_space = VmSpace::<PerPtMeta>::new();
        let boundary = page_size_at(2);
        insert_mapping(&child_space, boundary..boundary + p, 1);
        // Parent metadata finds the next child, but its start equals end.
        for end in [boundary - p, boundary] {
            check_case(&child_space, 0, end, HIGHEST_PAGING_LEVEL, None, (0, 2));
        }
    }

    #[ktest]
    fn aux_projection_empty_child_then_sibling() {
        let space = VmSpace::<PerPtMeta>::new();
        let p = page_size_at(1);
        let boundary = page_size_at(2);
        allocate_child(&space, 0);
        insert_mapping(&space, boundary..boundary + p, 1);
        check_case(
            &space,
            0,
            boundary + p,
            HIGHEST_PAGING_LEVEL,
            Some(boundary..boundary + p),
            (boundary, 1),
        );
        check_case(
            &space,
            boundary,
            boundary + p,
            HIGHEST_PAGING_LEVEL,
            Some(boundary..boundary + p),
            (boundary, 1),
        );
    }

    #[ktest]
    fn aux_projection_exhausted_child_then_sibling() {
        let space = VmSpace::<PerPtMeta>::new();
        let p = page_size_at(1);
        let boundary = page_size_at(2);
        insert_mapping(&space, p..2 * p, 1);
        insert_mapping(&space, boundary..boundary + p, 1);
        // Start in an already descended child after its final mapping. The
        // walker must pop and skip this exact child, then visit its sibling.
        for initial in [1, HIGHEST_PAGING_LEVEL] {
            check_case(
                &space,
                2 * p,
                boundary + p,
                initial,
                Some(boundary..boundary + p),
                (boundary, 1),
            );
        }
    }

    #[ktest]
    fn aux_projection_nested_exhausted_children() {
        let space = VmSpace::<PerPtMeta>::new();
        let p = page_size_at(1);
        let boundary = page_size_at(3);
        allocate_child(&space, 0);
        insert_mapping(&space, boundary..boundary + p, 1);
        // Exhaust both the level-1 and level-2 descendants before crossing
        // the level-3 entry boundary into a different child subtree.
        for initial in [1, HIGHEST_PAGING_LEVEL] {
            check_case(
                &space,
                p,
                boundary + p,
                initial,
                Some(boundary..boundary + p),
                (boundary, 1),
            );
        }
    }

    #[ktest]
    fn aux_projection_end_inside_or_at_empty_child_boundary() {
        let space = VmSpace::<PerPtMeta>::new();
        let p = page_size_at(1);
        let boundary = page_size_at(2);
        allocate_child(&space, 0);
        insert_mapping(&space, boundary..boundary + p, 1);
        for end in [p, boundary] {
            for initial in [1, HIGHEST_PAGING_LEVEL] {
                check_case(&space, 0, end, initial, None, (0, 2));
            }
        }
    }

    #[ktest]
    fn aux_projection_exhausted_subtree_reaches_root() {
        let space = VmSpace::<PerPtMeta>::new();
        let p = page_size_at(1);
        insert_mapping(&space, p..2 * p, 1);
        // With no remaining metadata, each exhausted child is skipped. This
        // is the resulting position, not necessarily the caller's end.
        check_case(
            &space,
            2 * p,
            root_range().end,
            1,
            None,
            (page_size_at(HIGHEST_PAGING_LEVEL), HIGHEST_PAGING_LEVEL),
        );
    }

    #[ktest]
    fn aux_projection_split_mapping_across_child_boundary() {
        let space = VmSpace::<PerPtMeta>::new();
        let p = page_size_at(1);
        let unit = page_size_at(2);
        let boundary = 2 * unit;
        let mapping = unit..3 * unit;
        insert_mapping(&space, mapping.clone(), 2);
        check_case(
            &space,
            boundary,
            mapping.end,
            HIGHEST_PAGING_LEVEL,
            Some(mapping.clone()),
            (boundary, 2),
        );
        // Real Aux allocation splits the original mapping at child boundaries.
        allocate_child(&space, boundary - p);
        allocate_child(&space, boundary);
        check_case(
            &space,
            boundary - p,
            mapping.end,
            HIGHEST_PAGING_LEVEL,
            Some(unit..boundary),
            (boundary - p, 1),
        );
        check_case(
            &space,
            boundary,
            mapping.end,
            HIGHEST_PAGING_LEVEL,
            Some(boundary..3 * unit),
            (boundary, 1),
        );
    }

    #[ktest]
    fn aux_projection_result_can_borrow_owned_capture_context() {
        let space = VmSpace::<PerPtMeta>::new();
        let p = page_size_at(1);
        insert_mapping(&space, p..2 * p, HIGHEST_PAGING_LEVEL);
        let context = Box::new(123usize);
        macro_rules! check_cursor_kind {
            ($constructor:ident) => {{
                let token = Box::new(456usize);
                let context_ref = &*context;
                let guard = disable_preempt();
                let mut cursor = space.$constructor(&guard, &root_range()).unwrap();
                let (range, owned, borrowed) = cursor
                    .find_next_mapped_with(2 * p, move |mapping| {
                        (mapping.range(), token, context_ref)
                    })
                    .unwrap();
                // The result may borrow unrelated captured context, and survives
                // dropping the cursor; it does not borrow the mapping.
                drop(cursor);
                assert_eq!(range, p..2 * p);
                assert_eq!(*owned, 456);
                assert_eq!(*borrowed, 123);
            }};
        }
        check_cursor_kind!(cursor);
        check_cursor_kind!(cursor_mut);
    }
}
