// SPDX-License-Identifier: MPL-2.0

use core::ops::Range;

use ostd::{
    mm::{page_size_at, vm_space::VmQueriedItem},
    task::disable_preempt,
};

#[cfg(ktest)]
use super::accounting_tests;

use super::{PteRangeMeta, RsAsDelta, Vmar, VmarCursorMut};
use crate::{
    prelude::*,
    vm::vmar::{
        VMAR_CAP_ADDR,
        cursor::{CursorExt, propagate_if_needed, take_next_unmappable, unmap_count_rs_as},
        interval_set::Interval,
        util::get_intersected_range,
    },
};

impl Vmar {
    /// Clears all mappings.
    ///
    /// After being cleared, this VMAR will become an empty VMAR.
    pub(super) fn clear(&self) {
        let full_range = 0..VMAR_CAP_ADDR;

        let preempt_guard = disable_preempt();
        let mut cursor = self
            .vm_space
            .cursor_mut(&preempt_guard, &full_range)
            .unwrap();
        let old_rmap_entries =
            Self::snapshot_rmap_entries(&mut cursor, core::slice::from_ref(&full_range));

        // Detached page tables are reclaimed after an RCU grace period. Drop
        // their mappings now so file-close notifications and device teardown
        // are not delayed until some later quiescent state.
        while let Some(range) =
            cursor.find_next_mapped_with(full_range.end, |mapping| mapping.range())
        {
            cursor.aux_meta_mut().inner.take_one(&range.start);
            if cursor.jump(range.end).is_err() {
                break;
            }
        }
        cursor.jump(full_range.start).unwrap();
        cursor.adjust_level(cursor.guard_level());
        cursor.aux_meta_mut().inner.clear();

        while cursor
            .find_next_unmappable_subtree(full_range.end)
            .is_some()
        {
            cursor.unmap();
        }

        self.rss_counters
            .iter()
            .for_each(|counter| counter.reset_all_zero());

        self.mapped_vm_size.clear();

        cursor.flusher().dispatch_tlb_flush();
        cursor.flusher().sync_tlb_flush();

        self.refresh_rmap_entries(
            &mut cursor,
            old_rmap_entries,
            core::slice::from_ref(&full_range),
        );

        drop(cursor);
        drop(preempt_guard);
    }

    /// Destroys all mappings that fall within the specified
    /// range in bytes.
    ///
    /// The range's start and end addresses must be page-aligned.
    ///
    /// Mappings may fall partially within the range; only the overlapped
    /// portions of the mappings are unmapped.
    pub(crate) fn remove_mapping(&self, range: Range<usize>) -> Result<()> {
        let preempt_guard = disable_preempt();
        let mut cursor = self.vm_space.cursor_mut(&preempt_guard, &range).unwrap();
        let mut rs_as_delta = RsAsDelta::new(self);
        #[cfg(feature = "lazy_tlb_flush_on_unmap")]
        if range.len() == PAGE_SIZE {
            let can_defer = cursor.find_next_mapped(range.end).is_some_and(|mapping| {
                mapping.map_to_addr() <= range.start
                    && mapping.map_end() >= range.end
                    && !mapping.is_shared()
                    && matches!(mapping.mapped_mem(), super::MappedMemory::Anonymous)
            });
            cursor.jump(range.start).unwrap();
            if can_defer {
                let mapping = take_next_unmappable(&mut cursor, range.end)
                    .unwrap()
                    .unwrap_mapping();
                mapping.unmap(&mut cursor, &mut rs_as_delta);
                cursor.complete_deferred_unmap();
                // Private anonymous mappings have no reverse-map entries.
                drop(rs_as_delta);
                drop(cursor);
                drop(preempt_guard);
                #[cfg(ktest)]
                self.accounting_pause.hit(accounting_tests::AFTER_UNMAP_PT);
                return Ok(());
            }
        }
        let old_rmap_entries =
            Self::snapshot_rmap_entries(&mut cursor, core::slice::from_ref(&range));

        let result = self.remove_mappings(&mut cursor, range.len(), &mut rs_as_delta);
        // Removal cannot create a reverse mapping. Preserve registration
        // updates whenever the old snapshot contained any shared mappings.
        if !old_rmap_entries.is_empty() {
            self.refresh_rmap_entries(&mut cursor, old_rmap_entries, core::slice::from_ref(&range));
        }

        drop(rs_as_delta);
        drop(cursor);
        drop(preempt_guard);
        #[cfg(ktest)]
        self.accounting_pause.hit(accounting_tests::AFTER_UNMAP_PT);

        result
    }

    /// Removes mappings in the given range using the provided cursor.
    ///
    /// if `dealloc` is true, it also deallocates the removed mappings' ranges
    /// to the allocator.
    pub(super) fn remove_mappings(
        &self,
        cursor: &mut VmarCursorMut<'_>,
        len: usize,
        rs_as_delta: &mut RsAsDelta,
    ) -> Result<()> {
        let range = cursor.virt_addr()..cursor.virt_addr() + len;

        while let Some(meta) = take_next_unmappable(cursor, range.end) {
            match meta {
                PteRangeMeta::ChildPt(range) => {
                    let cur_page_size = page_size_at(cursor.level());
                    for child_va in range.step_by(cur_page_size) {
                        cursor.jump(child_va).unwrap();

                        // Temporarily insert the `ChildPt` meta back to allow
                        // `unmap_count_rs_as` correctly navigating the child page table.
                        cursor
                            .aux_meta_mut()
                            .inner
                            .insert(PteRangeMeta::ChildPt(child_va..child_va + cur_page_size));
                        let num_unmapped =
                            unmap_count_rs_as(cursor, child_va + cur_page_size, rs_as_delta);
                        cursor.aux_meta_mut().inner.take_one(&child_va).unwrap();

                        let num_cursor_unmapped = cursor.unmap();

                        debug_assert_eq!(num_unmapped, num_cursor_unmapped);
                    }
                }
                PteRangeMeta::VmMapping(vm_mapping) => {
                    let taken_range = vm_mapping.range();

                    vm_mapping.unmap(cursor, rs_as_delta);

                    if cursor.jump(taken_range.end).is_err() {
                        break;
                    };
                }
            }
        }

        cursor.flusher().dispatch_tlb_flush();
        cursor.flusher().sync_tlb_flush();

        Ok(())
    }

    /// Discards all pages in the mappings that fall within the specified
    /// range in bytes.
    ///
    /// The pages will be reloaded from a clean state by the page fault
    /// handler if they are accessed later.
    ///
    /// The range's start and end addresses must be page-aligned.
    ///
    /// Mappings may fall partially within the range; only the pages in the
    /// overlapped portions of the mappings are discarded.
    ///
    /// If the range contains unmapped pages, an [`ENOMEM`] error will be returned.
    /// Note that all other pages are still discarded.
    ///
    /// [`ENOMEM`]: Errno::ENOMEM
    pub(crate) fn discard_pages(&self, range: Range<usize>) -> Result<()> {
        debug_assert!(range.start.is_multiple_of(PAGE_SIZE));
        debug_assert!(range.end.is_multiple_of(PAGE_SIZE));

        let mut last_mapping_end = range.start;

        let preempt_guard = disable_preempt();
        let mut cursor = self.vm_space.cursor_mut(&preempt_guard, &range).unwrap();
        let mut rs_as_delta = RsAsDelta::new(self);

        while let Some((vm_mapping_range, rss_type)) =
            cursor.find_next_mapped_with(range.end, |mapping| (mapping.range(), mapping.rss_type()))
        {
            // The range may contain pages that are not mapped. According to Linux behavior, this
            // is not a fault. However, an `ENOMEM` should be reported at the end.
            if last_mapping_end >= vm_mapping_range.start {
                last_mapping_end = vm_mapping_range.end;
            }

            let intersected_range = get_intersected_range(&range, &vm_mapping_range);

            cursor.jump(intersected_range.start).unwrap();

            while let Some(va) = cursor.find_next(intersected_range.end) {
                propagate_if_needed(&mut cursor, intersected_range.end - va);
                let page_size = page_size_at(cursor.level());
                let is_ram = matches!(cursor.query(), VmQueriedItem::MappedRam { .. });
                let num_unmapped = cursor.unmap();
                if is_ram {
                    rs_as_delta.add_rs(rss_type, -(num_unmapped as isize));
                    // Propagation can split the original mapping among child
                    // page tables. Account against the fragment owning this
                    // PTE while the cursor is still on that fragment.
                    let Some(PteRangeMeta::VmMapping(mapping)) =
                        cursor.aux_meta_mut().inner.find_one_mut(&va)
                    else {
                        panic!("unmapped RAM page has no owning mapping");
                    };
                    mapping.dec_frames_mapped(num_unmapped);
                }

                if va + page_size < intersected_range.end {
                    cursor.jump(va + page_size).unwrap();
                } else {
                    break;
                }
            }

            if cursor.jump(intersected_range.end).is_err() {
                break;
            }
        }

        // Discard leaves the VMA present. A subsequent access must fault and
        // reload clean contents, including when a hole causes ENOMEM below.
        cursor.flusher().dispatch_tlb_flush();
        cursor.flusher().sync_tlb_flush();

        if last_mapping_end < range.end {
            return_errno_with_message!(
                Errno::ENOMEM,
                "the range contains pages that are not mapped"
            )
        }

        Ok(())
    }
}
