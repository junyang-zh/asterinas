// SPDX-License-Identifier: MPL-2.0

use core::{array, ops::Range};

use aster_util::per_cpu_counter::PerCpuCounter;
use ostd::{
    cpu::PinCurrentCpu,
    mm::{
        CachePolicy, PageFlags, page_size_at,
        tlb::TlbFlushOp,
        vm_space::{CursorMut, VmQueriedItem},
    },
    task::disable_preempt,
};

use super::{PerPtMeta, Vmar, as_accounting::MappingSize};
use crate::{
    prelude::*,
    process::ProcessVm,
    vm::vmar::{
        VMAR_CAP_ADDR, VmarHandle, VmarSpace, cursor::CursorExt, interval_set::Interval,
        vm_allocator::VirtualAddressAllocator,
    },
};

impl Vmar {
    /// Creates a new VMAR whose content is inherited from another
    /// using copy-on-write (COW) technique.
    pub(crate) fn fork_from(vmar: &Self) -> Result<VmarHandle> {
        // Obtain the heap lock and hold it for the entire method to avoid race conditions.
        let heap_guard = vmar.process_vm.heap().lock();

        // Allocate new data structures.
        let new_vm_space = Arc::new(VmarSpace::new());
        let rss_counters = array::from_fn(|_| PerCpuCounter::new());

        // Lock both VM spaces.
        let preempt_guard = disable_preempt();
        // Auxiliary metadata is arranged by complete page-table nodes, so the
        // cursor must cover the complete user page-table range as well.
        const RANGE: Range<Vaddr> = 0..VMAR_CAP_ADDR;
        let mut new_cursor = new_vm_space.cursor_mut(&preempt_guard, &RANGE).unwrap();
        let cur_vm_space = vmar.vm_space();
        let mut cur_cursor = cur_vm_space.cursor_mut(&preempt_guard, &RANGE).unwrap();

        // Clone the data structures.
        let allocator = VirtualAddressAllocator::fork_from(&vmar.allocator)?;
        let cur_cpu = preempt_guard.current_cpu();
        rss_counters
            .iter()
            .zip(vmar.rss_counters.iter())
            .for_each(|(new, old)| {
                new.add_on_cpu(cur_cpu, old.sum_all_cpus() as isize);
            });
        let vm_size_total = vmar.get_mappings_total_size();
        let mapped_vm_size = MappingSize::new(vm_size_total)?;
        let process_vm = ProcessVm::fork_from(&vmar.process_vm, &heap_guard);
        let new_vmar = Arc::new_cyclic(|weak_self| Vmar {
            vm_space: new_vm_space.clone(),
            allocator,
            mapped_vm_size,
            rss_counters,
            process_vm,
            num_handles: core::sync::atomic::AtomicUsize::new(1),
            weak_self: weak_self.clone(),
            #[cfg(ktest)]
            accounting_pause: super::accounting_tests::Pause::new(),
        });

        // Clone mappings.
        let changes = cow_copy_pt(&mut cur_cursor, &mut new_cursor);
        if changes.parent_write_protected {
            // Other CPUs can retain a writable translation until the synchronous
            // invalidation finishes. Both complete VM spaces remain locked here.
            cur_cursor.flusher().issue_tlb_flush(TlbFlushOp::for_all());
            cur_cursor.flusher().dispatch_tlb_flush();
            cur_cursor.flusher().sync_tlb_flush();
        }

        // Each mapping is copied once into this unpublished child. Register its
        // shared VMO aliases before releasing either full-range cursor.
        for (vmo, entry) in changes.child_reverse_maps {
            vmo.rmap().lock().insert(new_vmar.weak_self.clone(), entry);
        }

        drop(cur_cursor);
        drop(new_cursor);
        drop(preempt_guard);

        Ok(VmarHandle::from_arc(new_vmar))
    }
}

#[derive(Default)]
struct ForkPageChanges {
    parent_write_protected: bool,
    child_reverse_maps: Vec<(Arc<super::Vmo>, super::RmapEntry)>,
}

/// Copies page-table mappings and metadata, recording pending parent
/// permission invalidations and child reverse-map registrations.
fn cow_copy_pt(
    src: &mut CursorMut<'_, PerPtMeta>,
    dst: &mut CursorMut<'_, PerPtMeta>,
) -> ForkPageChanges {
    let mut changes = ForkPageChanges::default();
    while let Some(src_vm_mapping) = src.find_next_mapped(VMAR_CAP_ADDR) {
        let vm_mapping_range = src_vm_mapping.range();
        let new_vm_mapping = src_vm_mapping.new_fork();
        if let Some(entry) = new_vm_mapping.rmap_entry_in(&vm_mapping_range) {
            changes.child_reverse_maps.push(entry);
        }
        let is_device = matches!(src_vm_mapping.mapped_mem(), super::MappedMemory::Device(_));
        let level = src.level();

        dst.jump(vm_mapping_range.start).unwrap();
        dst.adjust_level(level);
        dst.aux_meta_mut().insert_without_try_merge(new_vm_mapping);

        src.jump(vm_mapping_range.start).unwrap();

        changes.parent_write_protected |= cow_copy_mappings(src, dst, vm_mapping_range.end, !is_device);

        if src.jump(vm_mapping_range.end).is_err() {
            break;
        }
    }
    changes
}

/// Sets mappings in the source page table as read-only to trigger COW, and
/// copies the mappings to the destination page table.
fn cow_copy_mappings(
    src: &mut CursorMut<'_, PerPtMeta>,
    dst: &mut CursorMut<'_, PerPtMeta>,
    end: usize,
    copy_on_write: bool,
) -> bool {
    let mut parent_write_protected = false;
    debug_assert_eq!(src.level(), dst.level());
    debug_assert_eq!(src.virt_addr(), dst.virt_addr());

    fn op(flags: &mut PageFlags, _cache: &mut CachePolicy) {
        *flags -= PageFlags::W;
    }

    while let Some(mapped_va) = src.find_next(end) {
        let mapped_size = match src.query() {
            VmQueriedItem::MappedRam { frame, mut prop } => {
                let frame = (*frame).clone();
                let mapped_size = page_size_at(frame.map_level());

                if copy_on_write && prop.flags.contains(PageFlags::W) {
                    src.protect(op);
                    op(&mut prop.flags, &mut prop.cache);
                    parent_write_protected = true;
                }

                dst.jump(mapped_va).unwrap();
                dst.adjust_level(frame.map_level());
                dst.map(frame, prop);
                mapped_size
            }
            VmQueriedItem::MappedIoMem { paddr, prop, level } => {
                // For MMIO pages, find the corresponding `IoMem` and map it
                let (iomem, offset) = src.find_iomem_by_paddr(paddr).unwrap();
                let mapped_size = page_size_at(level);
                dst.jump(mapped_va).unwrap();
                dst.map_iomem(iomem, prop, mapped_size, offset);
                mapped_size
            }
            _ => {
                unreachable!("mapped item found but query failed")
            }
        };

        if mapped_va + mapped_size >= end {
            break;
        }

        if src.jump(mapped_va + mapped_size).is_err() {
            break;
        }
    }
    parent_write_protected
}

#[cfg(ktest)]
mod test {
    use ostd::{
        io::IoMem,
        mm::{FrameAllocOptions, PageProperty},
        prelude::*,
    };

    use super::*;

    #[ktest]
    fn repeated_cow_copy_only_flushes_new_write_downgrades() {
        let parent = VmarSpace::new();
        let pin = disable_preempt();
        let base = 4 * PAGE_SIZE;
        let range = base..base + 3 * PAGE_SIZE;
        for (index, flags) in [(0, PageFlags::R), (2, PageFlags::RW)] {
            let slot = base + index * PAGE_SIZE;
            let mut cursor = parent.cursor_mut(&pin, &(slot..slot + PAGE_SIZE)).unwrap();
            cursor.map(FrameAllocOptions::default().alloc_frame().unwrap().into(),
                       PageProperty::new_user(flags, CachePolicy::Writeback));
        }
        for first_fork in [true, false] {
            let child = VmarSpace::new();
            let mut src = parent.cursor_mut(&pin, &range).unwrap();
            let mut dst = child.cursor_mut(&pin, &range).unwrap();
            assert_eq!(cow_copy_mappings(&mut src, &mut dst, range.end, true), first_fork);
            for slot in [base, base + 2 * PAGE_SIZE] {
                src.jump(slot).unwrap();
                dst.jump(slot).unwrap();
                let VmQueriedItem::MappedRam { frame: parent_frame, prop: parent_prop } = src.query() else { panic!("missing parent page") };
                let VmQueriedItem::MappedRam { frame: child_frame, prop: child_prop } = dst.query() else { panic!("missing child page") };
                assert_eq!(child_frame.paddr(), parent_frame.paddr());
                assert_eq!(parent_prop.flags, PageFlags::R);
                assert_eq!(child_prop.flags, PageFlags::R);
            }
        }
    }

    #[ktest]
    fn copy_mappings_basic() {
        let vm_space = VmarSpace::new();
        let map_range = PAGE_SIZE..(PAGE_SIZE * 2);
        let cow_range = 0..PAGE_SIZE * 512 * 512;
        let page_property = PageProperty::new_user(PageFlags::RW, CachePolicy::Writeback);
        let preempt_guard = disable_preempt();

        // Allocates and maps a frame.
        let frame = FrameAllocOptions::default().alloc_frame().unwrap();
        let paddr = frame.paddr();
        let frame_clone_for_assert = frame.clone();

        vm_space
            .cursor_mut(&preempt_guard, &map_range)
            .unwrap()
            .map(frame.into(), page_property); // Original frame moved here

        // Confirms the initial mapping.
        assert!(matches!(
            vm_space.cursor(&preempt_guard, &map_range).unwrap().query(),
            VmQueriedItem::MappedRam { frame, prop } if frame.paddr() == paddr && prop.flags == PageFlags::RW
        ));

        // Creates a child page table with copy-on-write protection.
        let child_space = VmarSpace::new();
        {
            let mut child_cursor = child_space.cursor_mut(&preempt_guard, &cow_range).unwrap();
            let mut parent_cursor = vm_space.cursor_mut(&preempt_guard, &cow_range).unwrap();
            cow_copy_mappings(&mut parent_cursor, &mut child_cursor, cow_range.end, true);
        };

        // Confirms that parent and child VAs map to the same physical address.
        {
            let child_map_frame_addr = {
                let mut cursor = child_space.cursor(&preempt_guard, &map_range).unwrap();
                let VmQueriedItem::MappedRam { frame, .. } = cursor.query() else {
                    panic!("Child mapping query failed");
                };
                frame.paddr()
            };
            let parent_map_frame_addr = {
                let mut cursor = vm_space.cursor(&preempt_guard, &map_range).unwrap();
                let VmQueriedItem::MappedRam { frame, .. } = cursor.query() else {
                    panic!("Parent mapping query failed");
                };
                frame.paddr()
            };
            assert_eq!(child_map_frame_addr, parent_map_frame_addr);
            assert_eq!(child_map_frame_addr, paddr);
        }

        // Unmaps the page from the parent.
        vm_space
            .cursor_mut(&preempt_guard, &map_range)
            .unwrap()
            .unmap();

        // Confirms that the child VA remains mapped.
        assert!(matches!(
            child_space.cursor(&preempt_guard, &map_range).unwrap().query(),
            VmQueriedItem::MappedRam { frame, prop } if frame.paddr() == paddr && prop.flags == PageFlags::R
        ));

        // Creates a sibling page table (from the now-modified parent).
        let sibling_space = VmarSpace::new();
        {
            let mut sibling_cursor = sibling_space
                .cursor_mut(&preempt_guard, &cow_range)
                .unwrap();
            let mut parent_cursor = vm_space.cursor_mut(&preempt_guard, &cow_range).unwrap();
            cow_copy_mappings(
                &mut parent_cursor,
                &mut sibling_cursor,
                cow_range.len(),
                true,
            );
        }

        // Verifies that the sibling is unmapped as it was created after the parent unmapped the range.
        assert!(
            sibling_space
                .cursor(&preempt_guard, &map_range)
                .unwrap()
                .query()
                .is_none()
        );

        // Drops the parent page table.
        drop(vm_space);

        // Confirms that the child VA remains mapped after the parent is dropped.
        assert!(matches!(
            child_space.cursor(&preempt_guard, &map_range).unwrap().query(),
            VmQueriedItem::MappedRam { frame, prop } if frame.paddr() == paddr && prop.flags == PageFlags::R
        ));

        // Unmaps the page from the child.
        child_space
            .cursor_mut(&preempt_guard, &map_range)
            .unwrap()
            .unmap();

        // Maps the range in the sibling using the third clone.
        sibling_space
            .cursor_mut(&preempt_guard, &map_range)
            .unwrap()
            .map(frame_clone_for_assert.into(), page_property);

        // Confirms that the sibling mapping points back to the original frame's physical address.
        assert!(matches!(
            sibling_space.cursor(&preempt_guard, &map_range).unwrap().query(),
            VmQueriedItem::MappedRam { frame, prop } if frame.paddr() == paddr && prop.flags == PageFlags::RW
        ));

        // Confirms that the child remains unmapped.
        assert!(
            child_space
                .cursor(&preempt_guard, &map_range)
                .unwrap()
                .query()
                .is_none()
        );
    }

    #[ktest]
    fn copy_mappings_iomem() {
        /// A very large address (1TiB) beyond typical physical memory for testing.
        const IOMEM_PADDR: usize = 0x100_000_000_000;

        let vm_space = VmarSpace::new();
        let map_range = PAGE_SIZE..(PAGE_SIZE * 2);
        let cow_range = 0..PAGE_SIZE * 512 * 512;
        let page_property = PageProperty::new_user(PageFlags::RW, CachePolicy::Uncacheable);
        let preempt_guard = disable_preempt();

        // Creates and maps an `IoMem` instead of a frame.
        let iomem = IoMem::acquire(IOMEM_PADDR..IOMEM_PADDR + PAGE_SIZE)
            .expect("Failed to acquire `IoMem` for testing");
        let iomem_clone_for_assert = iomem.clone();

        vm_space
            .cursor_mut(&preempt_guard, &map_range)
            .unwrap()
            .map_iomem(iomem.clone(), page_property, PAGE_SIZE, 0);

        // Confirms the initial mapping.
        assert!(matches!(
            vm_space.cursor(&preempt_guard, &map_range).unwrap().query(),
            VmQueriedItem::MappedIoMem { paddr, prop, .. }  if paddr == IOMEM_PADDR && prop.flags == PageFlags::RW
        ));

        // Creates a child page table with copy-on-write protection.
        let child_space = VmarSpace::new();
        {
            let mut child_cursor = child_space.cursor_mut(&preempt_guard, &cow_range).unwrap();
            let mut parent_cursor = vm_space.cursor_mut(&preempt_guard, &cow_range).unwrap();
            cow_copy_mappings(&mut parent_cursor, &mut child_cursor, cow_range.len(), true);
        };

        // Confirms that parent and child VAs map to the same physical address.
        {
            let child_map_paddr = {
                let VmQueriedItem::MappedIoMem { paddr, .. } = child_space
                    .cursor(&preempt_guard, &map_range)
                    .unwrap()
                    .query()
                else {
                    panic!("Child mapping query failed");
                };
                paddr
            };
            let parent_map_paddr = {
                let VmQueriedItem::MappedIoMem { paddr, .. } =
                    vm_space.cursor(&preempt_guard, &map_range).unwrap().query()
                else {
                    panic!("Parent mapping query failed");
                };
                paddr
            };
            assert_eq!(child_map_paddr, parent_map_paddr);
            assert_eq!(child_map_paddr, IOMEM_PADDR);
        }

        // Unmaps the range from the parent.
        vm_space
            .cursor_mut(&preempt_guard, &map_range)
            .unwrap()
            .unmap();

        // Confirms that the child VA remains mapped.
        assert!(matches!(
            child_space.cursor(&preempt_guard, &map_range).unwrap().query(),
            VmQueriedItem::MappedIoMem { paddr, prop, .. }  if paddr == IOMEM_PADDR && prop.flags == PageFlags::RW
        ));

        // Creates a sibling page table (from the now-modified parent).
        let sibling_space = VmarSpace::new();
        {
            let mut sibling_cursor = sibling_space
                .cursor_mut(&preempt_guard, &cow_range)
                .unwrap();
            let mut parent_cursor = vm_space.cursor_mut(&preempt_guard, &cow_range).unwrap();
            cow_copy_mappings(
                &mut parent_cursor,
                &mut sibling_cursor,
                cow_range.len(),
                true,
            );
        }

        // Verifies that the sibling is unmapped as it was created after the parent unmapped the range.
        assert!(
            sibling_space
                .cursor(&preempt_guard, &map_range)
                .unwrap()
                .query()
                .is_none()
        );

        // Drops the parent page table.
        drop(vm_space);

        // Confirms that the child VA remains mapped after the parent is dropped.
        assert!(matches!(
            child_space.cursor(&preempt_guard, &map_range).unwrap().query(),
            VmQueriedItem::MappedIoMem { paddr, prop, .. }  if paddr == IOMEM_PADDR && prop.flags == PageFlags::RW
        ));

        // Unmaps the range from the child.
        child_space
            .cursor_mut(&preempt_guard, &map_range)
            .unwrap()
            .unmap();

        // Maps the range in the sibling using the cloned IoMem.
        sibling_space
            .cursor_mut(&preempt_guard, &map_range)
            .unwrap()
            .map_iomem(iomem_clone_for_assert, page_property, PAGE_SIZE, 0);

        // Confirms that the sibling mapping points back to the original `IoMem`'s physical address.
        assert!(matches!(
            sibling_space.cursor(&preempt_guard, &map_range).unwrap().query(),
            VmQueriedItem::MappedIoMem { paddr, prop, .. }  if paddr == IOMEM_PADDR && prop.flags == PageFlags::RW
        ));

        // Confirms that the child remains unmapped.
        assert!(
            child_space
                .cursor(&preempt_guard, &map_range)
                .unwrap()
                .query()
                .is_none()
        );
    }
}
