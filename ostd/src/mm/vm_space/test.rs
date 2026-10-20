// SPDX-License-Identifier: MPL-2.0

use super::*;

macro_rules! assert_matches_mapped {
        ($cursor:expr, $frame:expr, $prop:expr) => {
            assert!(matches!(
                $cursor.query(),
                VmQueriedItem::MappedRam {
                    frame: __frame__,
                    prop: __prop__,
                    ..
                } if __frame__.paddr() == $frame.paddr() && __prop__ == $prop
            ));
        };
    }

/// Helper function to create a dummy `UFrame`.
fn create_dummy_frame() -> UFrame {
    let frame = crate::mm::FrameAllocOptions::new().alloc_frame().unwrap();
    let uframe: UFrame = frame.into();
    uframe
}

#[cfg(feature = "lazy_tlb_flush_on_unmap")]
#[ktest]
fn deferred_generations_saturate_without_eliding_publication_barriers() {
    let vmspace = VmSpace::<()>::new();
    vmspace.cpus.store(&CpuSet::new_full(), Ordering::Release);
    vmspace
        .deferred_issued
        .store(u64::MAX - 1, Ordering::Relaxed);
    vmspace
        .deferred_completed
        .store(u64::MAX - 1, Ordering::Relaxed);
    let preempt = disable_preempt();
    let range = 0x1000..0x2000;
    let prop = PageProperty::new_user(PageFlags::R, CachePolicy::Writeback);
    let mut cursor = vmspace.cursor_mut(&preempt, &range).unwrap();
    for _ in 0..3 {
        cursor.jump(range.start).unwrap();
        cursor.map(create_dummy_frame(), prop);
        assert_eq!(cursor.unmap(), 1);
        cursor.complete_deferred_unmap();
        assert_eq!(vmspace.deferred_issued.load(Ordering::Acquire), u64::MAX);
        cursor.sync_deferred_unmaps_before_publish();
        assert_eq!(vmspace.deferred_completed.load(Ordering::Acquire), u64::MAX);
        assert!(crate::mm::tlb::latr::pending_cpus_for_test().is_empty());

        // At saturation, equal watermarks cannot justify skipping a barrier.
        // Queue a retained frame without dispatching, preserving the origin's
        // pending bit until the barrier performs its own local invalidation.
        let frame = create_dummy_frame();
        {
            let _irq = crate::irq::disable_local();
            cursor.flusher.latr_with(
                TlbFlushOp::for_single(range.start),
                Frame::rcu_from_unsized(RcuDrop::new(frame.clone())),
            );
            assert!(crate::mm::tlb::latr::pending_cpus_for_test().contains(preempt.current_cpu()));
        }
        cursor.sync_deferred_unmaps_before_publish();
        assert!(crate::mm::tlb::latr::pending_cpus_for_test().is_empty());
        cursor.flusher.dispatch_tlb_flush();
        cursor.flusher.sync_tlb_flush();
    }
}

/// Creates a new `VmSpace` and verifies its initial state.
#[ktest]
fn vmspace_creation() {
    let vmspace = VmSpace::<()>::new();
    let range = 0x0..0x1000;
    let preempt_guard = disable_preempt();
    let mut cursor = vmspace
        .cursor(&preempt_guard, &range)
        .expect("failed to create the cursor");
    while cursor.push_level_if_exists().is_some() {}
    assert!(cursor.query().is_none());
    assert!(cursor.cur_va_range() == range);
}

/// Maps and unmaps a single page using `CursorMut`.
#[ktest]
fn vmspace_map_unmap() {
    let vmspace = VmSpace::<()>::new();
    let range = 0x1000..0x2000;
    let frame = create_dummy_frame();
    let prop = PageProperty::new_user(PageFlags::R, CachePolicy::Writeback);
    let preempt_guard = disable_preempt();

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        // Initially, the page should not be mapped.
        while cursor_mut.push_level_if_exists().is_some() {}
        assert!(cursor_mut.query().is_none());
        assert!(cursor_mut.cur_va_range() == range);
        // Maps a frame.
        cursor_mut.map(frame.clone(), prop);
    }

    // Queries the mapping.
    {
        let mut cursor = vmspace
            .cursor(&preempt_guard, &range)
            .expect("failed to create the cursor");
        assert_eq!(cursor.virt_addr(), range.start);
        assert_matches_mapped!(cursor, frame, prop);
    }

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        // Unmaps the frame.
        cursor_mut.unmap();
    }

    // Queries to ensure it's unmapped.
    let mut cursor = vmspace
        .cursor(&preempt_guard, &range)
        .expect("failed to create the cursor");
    while cursor.push_level_if_exists().is_some() {}
    assert!(cursor.query().is_none());
    assert!(cursor.cur_va_range() == range);
}

/// A nonblocking cursor attempt reports overlap and releases partial locks.
#[ktest]
fn try_cursor_mut_reports_contention_without_leaking_locks() {
    let vmspace = VmSpace::<()>::new();
    let preempt_guard = disable_preempt();
    // Use sub-2-MiB ranges so each cursor locks a separate level-1 node.
    let rollback_probe = 0x20_0000..0x20_1000;
    let locked_range = 0x40_0000..0x40_1000;
    let spanning_range = rollback_probe.start..locked_range.end;

    // Materialize the first child page table so that the spanning attempt
    // locks it before encountering contention in the second child.
    drop(vmspace.cursor_mut(&preempt_guard, &rollback_probe).unwrap());

    let cursor = vmspace.cursor_mut(&preempt_guard, &locked_range).unwrap();
    assert!(
        vmspace
            .try_cursor_mut(&preempt_guard, &spanning_range)
            .unwrap()
            .is_none()
    );

    // The failed spanning attempt must have rolled back its first-child lock.
    assert!(
        vmspace
            .try_cursor_mut(&preempt_guard, &rollback_probe)
            .unwrap()
            .is_some()
    );

    drop(cursor);
    assert!(
        vmspace
            .try_cursor_mut(&preempt_guard, &spanning_range)
            .unwrap()
            .is_some()
    );
}

/// Maps a page twice and unmaps twice using `CursorMut`.
#[ktest]
#[should_panic(expected = "mapping over an already mapped page")]
fn vmspace_map_twice() {
    let vmspace = VmSpace::<()>::new();
    let range = 0x1000..0x2000;
    let frame = create_dummy_frame();
    let prop = PageProperty::new_user(PageFlags::R, CachePolicy::Writeback);
    let preempt_guard = disable_preempt();

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        cursor_mut.map(frame.clone(), prop);
    }

    {
        let mut cursor = vmspace
            .cursor(&preempt_guard, &range)
            .expect("failed to create the cursor");
        assert_matches_mapped!(cursor, frame, prop);
    }

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        cursor_mut.map(frame.clone(), prop);
    }
}

/// Unmaps twice using `CursorMut`.
#[ktest]
fn vmspace_unmap_twice() {
    let vmspace = VmSpace::<()>::new();
    let range = 0x1000..0x2000;
    let frame = create_dummy_frame();
    let prop = PageProperty::new_user(PageFlags::R, CachePolicy::Writeback);
    let preempt_guard = disable_preempt();

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        cursor_mut.map(frame.clone(), prop);
    }

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        assert_eq!(cursor_mut.unmap(), 1);
    }

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        assert_eq!(cursor_mut.unmap(), 0);
    }

    let mut cursor = vmspace
        .cursor(&preempt_guard, &range)
        .expect("failed to create the cursor");
    while cursor.push_level_if_exists().is_some() {}
    assert!(cursor.query().is_none());
    assert!(cursor.cur_va_range() == range);
}

/// Activates and deactivates the `VmSpace` in single-CPU scenarios.
#[ktest]
fn vmspace_activate() {
    let vmspace = Arc::new(VmSpace::<()>::new());

    // Activates the VmSpace.
    vmspace.activate();
    assert_eq!(ACTIVATED_VM_SPACE_CPUSET.load(), Arc::as_ptr(&vmspace.cpus));

    // Deactivates the VmSpace.
    let vmspace2 = Arc::new(VmSpace::<()>::new());
    vmspace2.activate();
    assert_eq!(
        ACTIVATED_VM_SPACE_CPUSET.load(),
        Arc::as_ptr(&vmspace2.cpus)
    );
}

/// Tests the `flusher` method of `CursorMut`.
#[ktest]
fn cursor_mut_flusher() {
    let vmspace = VmSpace::<()>::new();
    let range = 0x4000..0x5000;
    let frame = create_dummy_frame();
    let prop = PageProperty::new_user(PageFlags::R, CachePolicy::Writeback);
    let preempt_guard = disable_preempt();

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        cursor_mut.map(frame.clone(), prop);
    }

    {
        // Verifies that the mapping exists.
        let mut cursor = vmspace
            .cursor(&preempt_guard, &range)
            .expect("failed to create the cursor");
        assert_matches_mapped!(cursor, frame, prop);
    }

    {
        // Flushes the TLB using a mutable cursor.
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        cursor_mut.flusher().issue_tlb_flush(TlbFlushOp::for_all());
        cursor_mut.flusher().dispatch_tlb_flush();
    }

    {
        // Verifies that the mapping still exists.
        let mut cursor = vmspace
            .cursor(&preempt_guard, &range)
            .expect("failed to create the cursor");
        assert_matches_mapped!(cursor, frame, prop);
    }
}

/// Verifies the `VmReader` and `VmWriter` interfaces.
#[ktest]
fn vmspace_reader_writer() {
    let vmspace = Arc::new(VmSpace::<()>::new());
    let range = 0x4000..0x5000;
    let preempt_guard = disable_preempt();
    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        let frame = create_dummy_frame();
        let prop = PageProperty::new_user(PageFlags::R, CachePolicy::Writeback);
        cursor_mut.map(frame, prop);
    }

    // Mocks the current page table paddr to match the VmSpace's root paddr.
    // Fails if the VmSpace is not the current task's user space.

    // Attempts to create a reader.
    let reader_result = vmspace.reader(0x4000, 0x1000);
    // Expects failure in a test environment.
    assert!(reader_result.is_err());

    // Attempts to create a writer.
    let writer_result = vmspace.writer(0x4000, 0x1000);
    assert!(writer_result.is_err());

    // Activates the VmSpace.
    vmspace.activate();

    // Attempts to create a reader.
    let reader_result = vmspace.reader(0x4000, 0x1000);
    assert!(reader_result.is_ok());
    // Attempts to create a writer.
    let writer_result = vmspace.writer(0x4000, 0x1000);
    assert!(writer_result.is_ok());

    // Attempts to create a reader with an out-of-range address.
    let reader_result = vmspace.reader(0x4000, usize::MAX);
    assert!(reader_result.is_err());
    // Attempts to create a writer with an out-of-range address.
    let writer_result = vmspace.writer(0x4000, usize::MAX);
    assert!(writer_result.is_err());
}

/// Creates overlapping cursors and verifies handling.
#[ktest]
fn overlapping_cursors() {
    let vmspace = VmSpace::<()>::new();
    let range1 = 0x5000..0x6000;
    let range2 = 0x5800..0x6800; // Overlaps with range1.
    let preempt_guard = disable_preempt();

    // Creates the first cursor.
    let _cursor1 = vmspace
        .cursor(&preempt_guard, &range1)
        .expect("failed to create first cursor");

    // Attempts to create the second overlapping cursor.
    let cursor2_result = vmspace.cursor(&preempt_guard, &range2);
    assert!(cursor2_result.is_err());
}

/// Protects a range of pages.
#[ktest]
fn protect() {
    let vmspace = VmSpace::<()>::new();
    let range = 0x7000..0x8000;
    let frame = create_dummy_frame();
    let preempt_guard = disable_preempt();
    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        let prop = PageProperty::new_user(PageFlags::RW, CachePolicy::Writeback);
        cursor_mut.map(frame.clone(), prop);
        cursor_mut.protect(|flags, _cache| {
            *flags = PageFlags::R;
        });
    }

    // Confirms that the property was updated.
    let mut cursor = vmspace
        .cursor(&preempt_guard, &range)
        .expect("failed to create the cursor");
    assert_matches_mapped!(
        cursor,
        frame,
        PageProperty::new_user(PageFlags::R, CachePolicy::Writeback)
    );
}

/// A very large address (16 TiB) beyond typical physical memory for testing.
const IOMEM_PADDR: usize = 0x100_000_000_000;

/// Maps and queries an `IoMem` using `CursorMut`.
#[ktest]
fn vmspace_map_query_iomem() {
    let vmspace = VmSpace::<()>::new();
    let range = 0x1000..0x2000;
    let iomem = IoMem::acquire(IOMEM_PADDR..IOMEM_PADDR + 0x1000).unwrap();
    let prop = PageProperty::new_user(PageFlags::RW, CachePolicy::Uncacheable);
    let preempt_guard = disable_preempt();

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        // Initially, the page should not be mapped.
        while cursor_mut.push_level_if_exists().is_some() {}
        assert!(cursor_mut.query().is_none());
        assert!(cursor_mut.cur_va_range() == range);
        // Maps the `IoMem`.
        cursor_mut.map_iomem(iomem.clone(), prop, 0x1000, 0);
    }

    // Queries the mapping.
    {
        let mut cursor = vmspace
            .cursor(&preempt_guard, &range)
            .expect("failed to create the cursor");
        assert_eq!(cursor.virt_addr(), range.start);
        while cursor.push_level_if_exists().is_some() {}
        let query_item = cursor.query();
        // The query result should be `VmQueriedItem::MappedIoMem`.
        assert!(matches!(
            query_item,
            VmQueriedItem::MappedIoMem { paddr, prop: query_prop, level }
            if paddr == IOMEM_PADDR && query_prop.flags == prop.flags && query_prop.cache == prop.cache && level == 1
        ));

        let query_range = cursor.cur_va_range();
        assert_eq!(query_range, range);
    }

    // Tests `find_iomem_by_paddr`.
    {
        let cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        let (found_iomem, offset) = cursor_mut.find_iomem_by_paddr(IOMEM_PADDR).unwrap();
        assert_eq!(found_iomem.paddr(), IOMEM_PADDR);
        assert_eq!(found_iomem.size(), 0x1000);
        assert_eq!(offset, 0);

        // Tests finding with an offset.
        let (found_iomem, offset) = cursor_mut.find_iomem_by_paddr(IOMEM_PADDR + 0x80).unwrap();
        assert_eq!(found_iomem.paddr(), IOMEM_PADDR);
        assert_eq!(found_iomem.size(), 0x1000);
        assert_eq!(offset, 0x80);

        // Tests finding non-existent address.
        assert!(
            cursor_mut
                .find_iomem_by_paddr(IOMEM_PADDR + 0x1000)
                .is_none()
        );
    }
}

/// Maps and queries an `IoMem` with an offset using `CursorMut`.
#[ktest]
fn vmspace_map_iomem_with_offset() {
    let vmspace = VmSpace::<()>::new();
    let range = 0x2000..0x3000;
    let iomem = IoMem::acquire(IOMEM_PADDR + 0x1000..IOMEM_PADDR + 0x3000).unwrap();
    let prop = PageProperty::new_user(PageFlags::RW, CachePolicy::Uncacheable);
    let preempt_guard = disable_preempt();

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        // Maps the `IoMem` with the offset.
        cursor_mut.map_iomem(iomem.clone(), prop, 0x1000, 0x1000);
    }

    // Queries the mapping.
    {
        let mut cursor = vmspace
            .cursor(&preempt_guard, &range)
            .expect("failed to create the cursor");
        while cursor.push_level_if_exists().is_some() {}
        let query_item = cursor.query();
        // The query result should be `VmQueriedItem::MappedIoMem`.
        assert!(matches!(
            query_item,
            VmQueriedItem::MappedIoMem { paddr, prop: query_prop, level }
            if paddr == IOMEM_PADDR + 0x2000 && query_prop.flags == prop.flags && query_prop.cache == prop.cache && level == 1
        ));

        let query_range = cursor.cur_va_range();
        assert_eq!(query_range, range);
    }

    // Tests `find_iomem_by_paddr` with an offset.
    {
        let cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        let (found_iomem, offset) = cursor_mut
            .find_iomem_by_paddr(IOMEM_PADDR + 0x2000)
            .unwrap();
        assert_eq!(found_iomem.paddr(), IOMEM_PADDR + 0x1000);
        assert_eq!(found_iomem.size(), 0x2000);
        assert_eq!(offset, 0x1000);
    }
}

/// Tests that the `IoMem` is not removed from the `VmSpace` when unmapped.
#[ktest]
fn vmspace_iomem_persistence() {
    let vmspace = VmSpace::<()>::new();
    let range = 0x3000..0x4000;
    let iomem = IoMem::acquire(IOMEM_PADDR + 0x3000..IOMEM_PADDR + 0x4000).unwrap();
    let prop = PageProperty::new_user(PageFlags::RW, CachePolicy::Uncacheable);
    let preempt_guard = disable_preempt();

    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        cursor_mut.map_iomem(iomem.clone(), prop, 0x1000, 0);
    }

    // Verifies the `IoMem` is in the `VmSpace`.
    {
        let cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        assert!(
            cursor_mut
                .find_iomem_by_paddr(IOMEM_PADDR + 0x3000)
                .is_some()
        );
    }

    // Unmaps the `IoMem`.
    {
        let mut cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        cursor_mut.unmap();
    }

    // Verifies the `IoMem` is still in the `VmSpace` (persistence).
    {
        let cursor_mut = vmspace
            .cursor_mut(&preempt_guard, &range)
            .expect("failed to create the mutable cursor");
        assert!(
            cursor_mut
                .find_iomem_by_paddr(IOMEM_PADDR + 0x3000)
                .is_some()
        );
    }
}

/// A 2 MiB base-page operation must not retain the generic L2 covering writer.
#[ktest]
fn base_page_cursor_locks_existing_sibling_leaves_independently() {
    let vmspace = VmSpace::<()>::new();
    let leaf_size = page_size_at(2);
    let first = leaf_size..2 * leaf_size;
    let sibling = 2 * leaf_size..3 * leaf_size;
    let guard = disable_preempt();
    for range in [&first, &sibling] {
        let mut cursor = vmspace.cursor_mut(&guard, range).unwrap();
        cursor.adjust_level(1);
    }

    {
        let cursor = vmspace.cursor_mut(&guard, &first).unwrap();
        assert_eq!(cursor.guard_level(), 2);
        assert!(vmspace.try_cursor_mut(&guard, &first).unwrap().is_none());
    }
    {
        let cursor = vmspace.cursor_mut_base_pages(&guard, &first).unwrap();
        assert_eq!(cursor.guard_level(), 1);
        assert_eq!(cursor.guard_va_range(), first);
        let sibling_cursor = vmspace
            .try_cursor_mut(&guard, &sibling)
            .unwrap()
            .expect("disjoint existing leaf must remain available");
        assert_eq!(sibling_cursor.guard_level(), 1);
        assert!(vmspace.try_cursor_mut(&guard, &first).unwrap().is_none());
    }
}

/// Huge PTEs still stop acquisition at their owner and can be split safely.
#[ktest]
fn base_page_cursor_splits_existing_huge_iomem() {
    let vmspace = VmSpace::<()>::new();
    let size = page_size_at(2);
    let range = size..2 * size;
    let paddr = IOMEM_PADDR + 4 * size;
    let iomem = IoMem::acquire(paddr..paddr + size).unwrap();
    let prop = PageProperty::new_user(PageFlags::RW, CachePolicy::Uncacheable);
    let guard = disable_preempt();
    vmspace
        .cursor_mut(&guard, &range)
        .unwrap()
        .map_iomem(iomem, prop, size, 0);
    {
        let mut cursor = vmspace.cursor_mut_base_pages(&guard, &range).unwrap();
        assert_eq!(cursor.guard_level(), 2);
        let VmQueriedItem::MappedIoMem {
            level: huge_level,
            paddr: huge_paddr,
            prop: huge_prop,
        } = cursor.query()
        else {
            panic!("expected huge I/O mapping");
        };
        assert_eq!(huge_level, 2);
        assert_eq!(huge_paddr, paddr);
        assert_eq!(huge_prop.flags, prop.flags);
        assert_eq!(huge_prop.cache, prop.cache);
        cursor.adjust_level(1);
        assert_eq!(cursor.level(), 1);
        let VmQueriedItem::MappedIoMem {
            level: small_level,
            paddr: small_paddr,
            prop: small_prop,
        } = cursor.query()
        else {
            panic!("expected split I/O mapping");
        };
        crate::early_println!(
            "I/O split: requested={:?}, huge=({:#x}, {:?}), small=({:#x}, {:?})",
            prop,
            huge_paddr,
            huge_prop,
            small_paddr,
            small_prop
        );
        assert_eq!(small_level, 1);
        assert_eq!(small_paddr, huge_paddr);
        // I/O encoding adds a private tag; splitting must preserve it too.
        assert_eq!(small_prop, huge_prop);
    }
    let cursor = vmspace.cursor_mut_base_pages(&guard, &range).unwrap();
    assert_eq!(cursor.guard_level(), 1);
}
