// SPDX-License-Identifier: MPL-2.0

#![short_vis_path::add(vmar)]

use core::{cmp::min, ops::Range};

use align_ext::AlignExt;
use ostd::{
    cpu_local,
    mm::{
        CachePolicy, Frame, FrameAllocOptions, PageFlags, PageProperty, UFrame,
        io::util::HasVmReaderWriter, page_size_at, tlb::TlbFlushOp, vm_space::VmQueriedItem,
    },
    task::disable_preempt,
};

use super::{MappedMemory, PteRangeMeta, RsAsDelta, VmMapping, Vmar, VmarCursorMut};
use crate::{
    fs::file::MappedObject,
    prelude::*,
    vm::{
        page_cache::{VmoCommitError, VmoMapMode},
        perms::VmPerms,
        vmar::{
            MapHandle,
            interval_set::Interval,
            userspace_range,
            vm_mapping::{DeviceMapping, VmoCommitHandle, map_device_pages},
        },
    },
};

#[derive(Debug)]
enum PfError {
    /// Needs IO by committing the page in [`crate::vm::page_cache::Vmo`].
    Retry {
        va: Vaddr,
        how_to: VmoCommitHandle,
    },
    Device {
        va: Vaddr,
        range: Range<Vaddr>,
        object: Arc<dyn MappedObject>,
    },
    HardError(Error),
}

struct PendingDeviceFault {
    range: Range<Vaddr>,
    object: Arc<dyn MappedObject>,
    pages: Vec<DeviceMapping>,
    result: Result<()>,
}

// Keep an unused zeroed fault frame on each CPU. Allocation and zeroing occur
// before cursor acquisition; only copying a COW page occurs under its PT lock.
cpu_local! {
    static FAULT_FRAME: core::cell::Cell<Option<Frame<()>>> = core::cell::Cell::new(None);
}

struct PreparedFrame(Option<Frame<()>>);

impl PreparedFrame {
    fn new() -> Self {
        let irq = ostd::irq::disable_local();
        Self(FAULT_FRAME.get_with(&irq).take())
    }

    fn replenish(&mut self) -> Result<()> {
        if self.0.is_none() {
            self.0 = Some(FrameAllocOptions::alloc_zeroed_fault_frame()?);
        }
        Ok(())
    }

    fn take(&mut self) -> Frame<()> {
        self.0.take().expect("fault frame prepared outside PT lock")
    }
}

impl Drop for PreparedFrame {
    fn drop(&mut self) {
        if let Some(frame) = self.0.take() {
            // Keep one unused zeroed frame. If this task migrated during the
            // fault, release any displaced spare after enabling local IRQs.
            let old = {
                let irq = ostd::irq::disable_local();
                FAULT_FRAME.get_with(&irq).replace(Some(frame))
            };
            drop(old);
        }
    }
}

impl Vmar {
    /// Handles a page fault.
    pub(crate) fn handle_page_fault(&self, page_fault_info: &PageFaultInfo) -> Result<()> {
        let address = page_fault_info.address;

        if !userspace_range().contains(&address) {
            return_errno_with_message!(
                Errno::EFAULT,
                "handle_page_fault: page fault address is not in userspace range"
            );
        }

        // Lock the entire level-1 PT so that we can handle page faults around.
        let range_start = address.align_down(page_size_at(2));
        let range_to_lock = range_start
            ..range_start
                .checked_add(page_size_at(2))
                .unwrap_or_else(|| userspace_range().end);

        let checked = self.vm_space.checked_range(&range_to_lock)?;

        // Retry is needed if the page fault needs I/O after we locked the page table.
        // Here we declare the state visible across retries. Take care of race
        // conditions when accessing such state.
        let mut range_handled = 0..0;
        let mut device_fault = None;
        let mut prepared = PreparedFrame::new();

        'retry: loop {
            prepared.replenish()?;
            let preempt_guard = disable_preempt();
            // Faults insert base pages only. Keep the whole fault-around range,
            // but allow disjoint existing leaf tables to be locked independently.
            let mut cursor = checked.cursor_mut_base_pages(&preempt_guard);
            let mut rs_as_delta = RsAsDelta::new(self);

            cursor.jump(address.align_down(PAGE_SIZE)).unwrap();
            while cursor.push_level_if_exists().is_some() {}

            let vacant_leaf = cursor.level() == 1 && matches!(cursor.query(), VmQueriedItem::None);
            let Some(PteRangeMeta::VmMapping(vm_mapping)) =
                cursor.aux_meta_mut().inner.find_one_mut(&address)
            else {
                return_errno_with_message!(
                    Errno::EACCES,
                    "handle_page_fault: no VM mappings contain the page fault address"
                );
            };

            // A missing PTE in an existing leaf needs no metadata delegation.
            // Install an ordinary private anonymous page while its mapping and
            // the prepared zeroed frame are both available under this cursor.
            if vacant_leaf
                && range_handled == (0..0)
                && !page_fault_info.is_forced()
                && !vm_mapping.handle_page_faults_around()
                && !vm_mapping.is_shared()
                && matches!(vm_mapping.mapped_mem(), MappedMemory::Anonymous)
                && vm_mapping.perms().contains(page_fault_info.required_perms)
            {
                let prop = fault_page_property(
                    vm_mapping.perms(),
                    page_fault_info.required_perms.contains(VmPerms::WRITE),
                );
                let rss_type = vm_mapping.rss_type();
                vm_mapping.add_frames_mapped(1);
                cursor.map(prepared.take().into(), prop);
                rs_as_delta.add_rs(rss_type, 1);
                cursor.flush_pending_tlb();
                break 'retry;
            }

            let range_to_handle = range_to_handle(vm_mapping, page_fault_info);
            if vacant_leaf
                && range_handled.is_empty()
                && range_to_handle.len() > PAGE_SIZE
                && try_read_private_cluster(
                    &mut cursor,
                    &range_to_handle,
                    page_fault_info,
                    &mut rs_as_delta,
                )
            {
                cursor.flush_pending_tlb();
                break 'retry;
            }
            if range_handled.is_empty() {
                range_handled = range_to_handle.start..range_to_handle.start;
            }
            if range_handled.end >= range_to_handle.end {
                // We might be racing with file resizing. We must have handled
                // the faulting page since `range_to_handle` always includes it.
                debug_assert!(range_to_handle.contains(&address));
                return Ok(());
            }

            for va in (range_handled.end..range_to_handle.end).step_by(PAGE_SIZE) {
                if prepared.0.is_none() {
                    drop(rs_as_delta);
                    drop(cursor);
                    drop(preempt_guard);
                    continue 'retry;
                }
                let res = handle_one_page(
                    &mut cursor,
                    va,
                    page_fault_info,
                    &mut rs_as_delta,
                    &mut device_fault,
                    &mut prepared,
                );

                match res {
                    Ok(_) => {}
                    Err(PfError::Retry { va, how_to }) => {
                        drop(rs_as_delta);
                        drop(cursor);
                        drop(preempt_guard);
                        let err = how_to.commit();
                        if let Err(e) = err {
                            if va == address.align_down(PAGE_SIZE) {
                                return Err(e);
                            } else {
                                // Ignore errors caused by surrounding pages.
                                // And don't retry this page again.
                                range_handled.end = va + PAGE_SIZE;
                            }
                        }
                        continue 'retry;
                    }
                    Err(PfError::Device { va, range, object }) => {
                        drop(rs_as_delta);
                        drop(cursor);
                        drop(preempt_guard);
                        // Device callbacks may take sleeping locks. Revalidate
                        // the mapping after reacquiring the cursor below.
                        let mut pages = Vec::new();
                        let result = object.handle_page_fault(
                            va - range.start,
                            MapHandle::new(range.len(), &mut pages),
                        );
                        device_fault = Some(PendingDeviceFault {
                            range,
                            object,
                            pages,
                            result,
                        });
                        continue 'retry;
                    }
                    Err(PfError::HardError(e)) => {
                        if va == address.align_down(PAGE_SIZE) {
                            return Err(e);
                        }
                    }
                }

                range_handled.end = va + PAGE_SIZE;
            }

            cursor.flush_pending_tlb();

            break 'retry;
        }

        Ok(())
    }
}

/// Page fault information converted from [`CpuException`].
///
/// `TryFrom<CpuException>` should be implemented for this struct.
/// If [`CpuException`] is a page fault, `try_from` should return `Ok(PageFaultInfo)`,
/// or `Err(())` (no error information) otherwise.
///
/// [`CpuException`]: ostd::arch::cpu::context::CpuException
#[derive(Debug)]
pub(crate) struct PageFaultInfo {
    /// The virtual address where a page fault occurred.
    pub(in vmar) address: Vaddr,

    /// The [`VmPerms`] required by the memory operation that causes page fault.
    /// For example, a "store" operation may require `VmPerms::WRITE`.
    pub(in vmar) required_perms: VmPerms,

    /// Whether this page fault is forced (e.g., manually triggered by `ptrace`).
    /// A forced page fault may bypass some permission checks.
    is_forced: bool,
}

impl PageFaultInfo {
    /// Creates a new `PageFaultInfo`.
    pub(crate) fn new(address: Vaddr, required_perms: VmPerms) -> Self {
        Self {
            address,
            required_perms,
            is_forced: false,
        }
    }

    /// Returns whether this page fault is forced.
    pub(in vmar) fn is_forced(&self) -> bool {
        self.is_forced
    }

    /// Marks this page fault as forced.
    pub(super) fn force(mut self) -> Self {
        self.is_forced = true;
        self
    }
}

fn range_to_handle(vm_mapping: &VmMapping, page_fault_info: &PageFaultInfo) -> Range<Vaddr> {
    let page_addr = page_fault_info.address.align_down(PAGE_SIZE);

    // Copy-on-write and shared-file dirtying apply to the addressed page.
    // Read faults can still populate nearby cached pages as read-only mappings.
    if page_fault_info.required_perms.contains(VmPerms::WRITE)
        || page_fault_info.is_forced()
        || !vm_mapping.handle_page_faults_around()
        || matches!(vm_mapping.mapped_mem(), MappedMemory::Device(_))
    {
        return page_addr..page_addr + PAGE_SIZE;
    }

    const SURROUNDING_PAGE_NUM: usize = 16;
    const SURROUNDING_PAGE_ADDR_MASK: usize = !(SURROUNDING_PAGE_NUM * PAGE_SIZE - 1);

    let window_start = page_addr & SURROUNDING_PAGE_ADDR_MASK;
    let start_addr = window_start.max(vm_mapping.map_to_addr());
    let end_addr = (window_start + SURROUNDING_PAGE_NUM * PAGE_SIZE).min(vm_mapping.map_end());

    let Some(vmo) = vm_mapping.vmo() else {
        return start_addr..end_addr;
    };

    let size = min(vmo.valid_size().unwrap_or(0), vm_mapping.map_size());
    let end_addr = end_addr.min(vm_mapping.map_to_addr() + size);

    // The page fault address falls outside the [`Vmo`] bounds.
    // Only a single page fault is handled in this situation.
    if end_addr <= page_addr {
        return page_addr..page_addr + PAGE_SIZE;
    }

    start_addr..end_addr
}

/// Walk the VMO and an existing leaf together for an ordinary private
/// read fault. The page-table lock keeps the mapping and all its permissions
/// stable throughout the cluster. A cache miss resumes normal fault handling.
fn try_read_private_cluster(
    cursor: &mut VmarCursorMut<'_>,
    range: &Range<Vaddr>,
    fault: &PageFaultInfo,
    delta: &mut RsAsDelta,
) -> bool {
    let Some(PteRangeMeta::VmMapping(mapping)) = cursor.aux_meta().inner.find_one(&range.start)
    else {
        return false;
    };
    if mapping.is_shared()
        || fault.is_forced()
        || fault.required_perms.contains(VmPerms::WRITE)
        || !mapping.perms().contains(fault.required_perms)
        || mapping.map_end() < range.end
    {
        return false;
    }
    let Some(mapped_vmo) = mapping.vmo() else {
        return false;
    };
    let Some(first) = mapped_vmo
        .offset()
        .checked_add(range.start - mapping.map_to_addr())
    else {
        return false;
    };
    let Some(end) = first.checked_add(range.len()) else {
        return false;
    };
    let vmo = mapped_vmo.vmo().clone();
    let mode = vmo_map_mode(mapping, false);
    let rss_type = mapping.rss_type();
    let prop = fault_page_property(mapping.perms() - VmPerms::WRITE, false);
    let mut next = range.start;
    let mut added = 0;
    let outcome = vmo.try_operate_on_range(
        &(first..end),
        |commit| {
            cursor.jump(next).unwrap();
            if matches!(cursor.query(), VmQueriedItem::None) {
                let (_, page) = commit()?;
                cursor.map(page.into(), prop);
                added += 1;
            }
            next += PAGE_SIZE;
            Ok(())
        },
        mode,
    );
    if added != 0 {
        let Some(PteRangeMeta::VmMapping(mapping)) =
            cursor.aux_meta_mut().inner.find_one_mut(&range.start)
        else {
            unreachable!("covered mapping changed within a locked leaf")
        };
        mapping.add_frames_mapped(added);
        delta.add_rs(rss_type, added as isize);
    }
    outcome.is_ok()
}

fn handle_one_page(
    cursor: &mut VmarCursorMut<'_>,
    va: Vaddr,
    page_fault_info: &PageFaultInfo,
    rs_as_delta: &mut RsAsDelta,
    device_fault: &mut Option<PendingDeviceFault>,
    prepared: &mut PreparedFrame,
) -> core::result::Result<(), PfError> {
    cursor.jump(va).unwrap();
    while cursor.push_level_if_exists().is_some() {}

    let Some(PteRangeMeta::VmMapping(vm_mapping)) = cursor.aux_meta().inner.find_one(&va) else {
        return Err(PfError::HardError(Error::with_message(
            Errno::EACCES,
            "handle_one_page: no VM mappings contain the page fault address",
        )));
    };

    let required_perms = page_fault_info.required_perms;

    let mut perms = vm_mapping.perms();

    // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/mm/gup.c#L1282-L1311>
    if page_fault_info.is_forced() {
        if perms.contains(VmPerms::MAY_READ) {
            perms.insert(VmPerms::READ);
        }
        if !vm_mapping.is_shared() && perms.contains(VmPerms::MAY_WRITE) {
            perms.insert(VmPerms::WRITE);
        }
    }

    if !perms.contains(page_fault_info.required_perms) {
        debug!(
            "perms {:?}, page_fault_info.required_perms {:?}, vm_mapping.range {:#x?}",
            perms,
            page_fault_info.required_perms,
            vm_mapping.range()
        );
        return Err(PfError::HardError(Error::with_message(
            Errno::EACCES,
            "perm check fails",
        )));
    }

    if let MappedMemory::Device(object) = vm_mapping.mapped_mem() {
        let range = vm_mapping.range();
        if let VmQueriedItem::MappedRam { prop, .. } | VmQueriedItem::MappedIoMem { prop, .. } =
            cursor.query()
            && VmPerms::from(prop.flags).contains(required_perms)
        {
            TlbFlushOp::for_range(va..va + PAGE_SIZE).perform_on_current();
            return Ok(());
        }
        let Some(pending) = device_fault
            .take()
            .filter(|pending| pending.range == range && Arc::ptr_eq(&pending.object, object))
        else {
            return Err(PfError::Device {
                va,
                range,
                object: object.clone(),
            });
        };
        // Acquisition descends through absent entries to L1. A huge PTE can
        // stop it earlier, but then this entire aligned fault range is mapped
        // and map_device_pages skips it. Empty device slots are therefore L1;
        // its per-slot I/O clipping inserts only base pages with this cursor.
        debug_assert!(cursor.level() == 1 || !matches!(cursor.query(), VmQueriedItem::None));
        let count = map_device_pages(cursor, &range, perms, pending.pages);
        rs_as_delta.add_rs(MapHandle::DEVICE_RSS_TYPE, count as isize);
        return pending.result.map_err(PfError::HardError);
    }

    let is_write = required_perms.contains(VmPerms::WRITE);
    let is_shared = vm_mapping.is_shared();

    // For shared mappings, ensure that the page cache allows the page to be
    // written and records it as dirty before granting write permission in the
    // page table. Do this before mutably borrowing the cursor metadata.
    if is_write
        && is_shared
        && let MappedMemory::Vmo(vmo) = vm_mapping.mapped_mem()
        && let Err(err) =
            vmo.get_committed_frame(va - vm_mapping.map_to_addr(), VmoMapMode::SharedWrite)
    {
        let page_idx = err.pending_index().map_err(PfError::HardError)?;
        return Err(PfError::Retry {
            va,
            how_to: vmo.dup_commit(page_idx, VmoMapMode::SharedWrite),
        });
    }

    cursor.adjust_level(1);
    let cur_va_range = cursor.cur_va_range().clone();
    debug_assert_eq!(cur_va_range, va..va + PAGE_SIZE);

    let item = cursor.query();
    match item {
        VmQueriedItem::MappedRam { frame, mut prop } => {
            if VmPerms::from(prop.flags).contains(required_perms) {
                // Another thread may have resolved the fault. Invalidate the
                // faulting address before retrying it. Already-present neighbors
                // are only visited for fault-around and their PTEs are unchanged.
                if va == page_fault_info.address.align_down(PAGE_SIZE) {
                    TlbFlushOp::for_range(cur_va_range).perform_on_current();
                }
                return Ok(());
            }
            assert!(is_write);

            // Skip if the page fault is already handled.
            if prop.flags.contains(PageFlags::W) {
                return Ok(());
            }

            // If the forked child or parent immediately unmaps the page after
            // the fork without accessing it, we are the only reference to the
            // frame. We can directly map the frame as writable without copying.
            let only_reference = frame.reference_count() == 1;

            let new_flags = PageFlags::W | PageFlags::ACCESSED | PageFlags::DIRTY;

            if is_shared || only_reference {
                cursor.protect(|flags, _cache| {
                    *flags |= new_flags;
                });
                cursor
                    .flusher()
                    .issue_tlb_flush(TlbFlushOp::for_range(cur_va_range));
            } else {
                let new_frame = duplicate_frame(&frame, prepared);
                prop.flags |= new_flags;
                // Hold the previous frame through the synchronous flush at
                // the end of this COW fault.
                let removed = cursor.unmap_for_synchronous_flush();
                debug_assert_eq!(removed, 1);
                cursor.map(new_frame.into(), prop);
            }
        }
        VmQueriedItem::MappedIoMem { .. } => {
            // The page of I/O memory is populated when the memory
            // mapping is created.
            return Err(PfError::HardError(Error::with_message(
                Errno::EFAULT,
                "device memory page faults cannot be resolved",
            )));
        }
        VmQueriedItem::None => {
            // Map a new frame to the page fault address.
            let PteRangeMeta::VmMapping(vm_mapping) =
                cursor.aux_meta_mut().inner.find_one_mut(&va).unwrap()
            else {
                unreachable!("`find_one` does not stop at `VmMapping`");
            };
            let page_aligned_addr = va.align_down(PAGE_SIZE);
            let (frame, is_readonly) =
                match prepare_page(vm_mapping, page_aligned_addr, is_write, prepared) {
                    Ok((frame, is_readonly)) => (frame, is_readonly),
                    Err(VmoCommitError::Err(e)) => return Err(PfError::HardError(e)),
                    Err(
                        VmoCommitError::NeedIo {
                            index: vmo_page_index,
                        }
                        | VmoCommitError::WaitUntilInit {
                            index: vmo_page_index,
                            ..
                        },
                    ) => {
                        let how_to = vm_mapping
                            .vmo()
                            .unwrap()
                            .dup_commit(vmo_page_index, vmo_map_mode(vm_mapping, is_write));
                        return Err(PfError::Retry { va, how_to });
                    }
                };

            let vm_perms = {
                let mut perms = vm_mapping.perms();
                if is_readonly {
                    // COW pages are forced to be read-only.
                    perms -= VmPerms::WRITE;
                }
                perms
            };

            let map_prop = fault_page_property(vm_perms, is_write);

            let rss_type = vm_mapping.rss_type();
            vm_mapping.add_frames_mapped(1);

            cursor.map(frame, map_prop);

            rs_as_delta.add_rs(rss_type, 1);
        }
        VmQueriedItem::PageTable => {
            unreachable!("pushed but still queried a page table")
        }
    }

    Ok(())
}

fn fault_page_property(perms: VmPerms, is_write: bool) -> PageProperty {
    let mut flags = PageFlags::from(perms) | PageFlags::ACCESSED;
    if is_write {
        flags |= PageFlags::DIRTY;
    }
    PageProperty::new_user(flags, CachePolicy::Writeback)
}

fn prepare_page(
    vm_mapping: &VmMapping,
    page_aligned_addr: Vaddr,
    write: bool,
    prepared: &mut PreparedFrame,
) -> core::result::Result<(UFrame, bool), VmoCommitError> {
    let mut is_readonly = false;

    let vmo = match vm_mapping.mapped_mem() {
        MappedMemory::Vmo(vmo) => vmo,
        MappedMemory::Anonymous => {
            // Anonymous mapping. Allocate a new frame.
            return Ok((prepared.take().into(), is_readonly));
        }
        MappedMemory::Device(_) => {
            // Device memory is populated when the memory mapping is created.
            return Err(VmoCommitError::Err(Error::with_message(
                Errno::EFAULT,
                "device memory page faults cannot be resolved",
            )));
        }
    };

    let page_offset = page_aligned_addr - vm_mapping.map_to_addr();
    if !vm_mapping.is_shared() && vmo.valid_size().is_none_or(|s| page_offset >= s) {
        // The page index is outside the VMO. This is only allowed in private mapping.
        return Ok((prepared.take().into(), is_readonly));
    }

    let (page, mode) = vmo.get_committed_frame(page_offset, vmo_map_mode(vm_mapping, write))?;
    if !vm_mapping.is_shared() && write {
        // Write access to private VMO-backed mapping. Performs COW directly.
        Ok((duplicate_frame(&page.into(), prepared).into(), is_readonly))
    } else {
        // Operations to shared mapping or read access to private VMO-backed mapping.
        // If read access to private VMO-backed mapping triggers a page fault,
        // the map should be readonly. If user next tries to write to the frame,
        // another page fault will be triggered which will performs a COW (Copy-On-Write).
        is_readonly = !vm_mapping.is_shared() || mode != VmoMapMode::SharedWrite;
        Ok((page.into(), is_readonly))
    }
}

fn vmo_map_mode(vm_mapping: &VmMapping, is_write: bool) -> VmoMapMode {
    if !vm_mapping.is_shared() {
        VmoMapMode::Private
    } else if is_write {
        VmoMapMode::SharedWrite
    } else {
        VmoMapMode::SharedRead
    }
}

fn duplicate_frame(src: &UFrame, prepared: &mut PreparedFrame) -> Frame<()> {
    let new_frame = prepared.take();
    new_frame.writer().write(&mut src.reader());
    new_frame
}

#[cfg(ktest)]
mod test {
    use core::num::NonZeroUsize;

    use ostd::prelude::ktest;

    use super::*;
    use crate::{
        fs::pseudofs::SockFs,
        process::ProcessVm,
        vm::vmar::{
            VmarHandle,
            vmar_impls::{OffsetType, RssType},
        },
    };

    fn new_vmar() -> VmarHandle {
        crate::time::clocks::init_for_ktest();
        crate::util::random::init();
        VmarHandle::new(ProcessVm::new(SockFs::new_path())).unwrap()
    }

    fn map_anon(vmar: &Vmar, range: Range<Vaddr>, perms: VmPerms) {
        assert_eq!(
            vmar.new_map(NonZeroUsize::new(range.len()).unwrap(), perms)
                .unwrap()
                .offset(range.start, OffsetType::FixedNoReplace)
                .build()
                .unwrap(),
            range.start
        );
    }

    #[ktest]
    fn bridge_two_resident_anonymous_neighbors_preserves_counts_and_permissions() {
        let vmar = new_vmar();
        let base = page_size_at(2);
        let perms = VmPerms::READ | VmPerms::WRITE;
        for index in [0, 2] {
            let start = base + index * PAGE_SIZE;
            map_anon(&vmar, start..start + PAGE_SIZE, perms);
            vmar.handle_page_fault(&PageFaultInfo::new(start, VmPerms::WRITE)).unwrap();
        }
        map_anon(&vmar, base + PAGE_SIZE..base + 2 * PAGE_SIZE, perms);
        map_anon(&vmar, base + 3 * PAGE_SIZE..base + 4 * PAGE_SIZE, VmPerms::READ);
        let mut seen = Vec::new();
        vmar.for_each_mapping(base..base + 4 * PAGE_SIZE, true, |mapping| {
            seen.push((mapping.map_to_addr(), mapping.map_size(), mapping.frames_mapped()));
        }).unwrap();
        assert_eq!(seen, [(base, 3 * PAGE_SIZE, Some(2)), (base + 3 * PAGE_SIZE, PAGE_SIZE, Some(0))]);
        assert!(vmar.handle_page_fault(&PageFaultInfo::new(base + 3 * PAGE_SIZE, VmPerms::WRITE)).is_err());
        vmar.remove_mapping(base..base + 4 * PAGE_SIZE).unwrap();
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 0);
    }

    #[ktest]
    fn protect_preserves_resident_page_status_and_write_faults() {
        let vmar = new_vmar();
        let addr = page_size_at(2);
        let range = addr..addr + PAGE_SIZE;
        let rw = VmPerms::READ | VmPerms::WRITE;
        map_anon(&vmar, range.clone(), rw);
        let write = || {
            vmar.handle_page_fault(&PageFaultInfo::new(addr, VmPerms::WRITE))
                .unwrap()
        };
        let flags = || {
            let guard = disable_preempt();
            let mut cursor = vmar.vm_space.cursor(&guard, &range).unwrap();
            while cursor.push_level_if_exists().is_some() {}
            match cursor.query() {
                VmQueriedItem::MappedRam { prop, .. } => prop.flags,
                _ => panic!("expected a resident anonymous page"),
            }
        };
        write();
        let history = PageFlags::ACCESSED | PageFlags::DIRTY;
        assert!(flags().contains(history | PageFlags::RW));
        vmar.protect(VmPerms::READ, range.clone()).unwrap();
        assert!(flags().contains(history | PageFlags::R));
        assert!(!flags().contains(PageFlags::W));
        vmar.protect(rw, range.clone()).unwrap();
        assert!(flags().contains(history));
        assert!(!flags().contains(PageFlags::W));
        write();
        assert!(flags().contains(history | PageFlags::RW));
    }

    #[ktest]
    fn protect_error_retains_mapping_and_prior_changes() {
        let vmar = new_vmar();
        let start = page_size_at(2);
        let split = start + PAGE_SIZE;
        let end = split + PAGE_SIZE;
        map_anon(&vmar, start..split, VmPerms::READ | VmPerms::WRITE);
        vmar.new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
            .unwrap()
            .may_perms(VmPerms::MAY_READ)
            .offset(split, OffsetType::FixedNoReplace)
            .build()
            .unwrap();
        let result = vmar.protect(VmPerms::READ | VmPerms::EXEC, start..end);
        assert_eq!(result.unwrap_err().error(), Errno::EACCES);
        let read = |addr| vmar.handle_page_fault(&PageFaultInfo::new(addr, VmPerms::READ));
        read(split).unwrap();
        read(start).unwrap();
        let write = vmar.handle_page_fault(&PageFaultInfo::new(start, VmPerms::WRITE));
        assert_eq!(write.unwrap_err().error(), Errno::EACCES);
    }

    /// Exercise actual metadata delegation, including a missing intermediate PT.
    #[ktest]
    fn first_fault_delegates_mapping_and_preserves_outside_fragments() {
        for owner_level in [2, 3] {
            let vmar = new_vmar();
            let unit = page_size_at(owner_level);
            let range = unit..4 * unit;
            let fault_addr = 2 * unit;
            let perms = VmPerms::READ | VmPerms::WRITE;
            map_anon(&vmar, range.clone(), perms);
            {
                let guard = disable_preempt();
                let mut cursor = vmar.vm_space.cursor_mut(&guard, &range).unwrap();
                assert_eq!(cursor.level(), owner_level);
                let Some(PteRangeMeta::VmMapping(mapping)) =
                    cursor.aux_meta().inner.find_one(&fault_addr)
                else {
                    panic!("unfaulted mapping must be owned by the parent");
                };
                assert_eq!(mapping.range(), range);
                assert_eq!(mapping.frames_mapped(), Some(0));
                cursor.jump(fault_addr).unwrap();
                assert!(matches!(cursor.query(), VmQueriedItem::None));
            }

            vmar.handle_page_fault(&PageFaultInfo::new(fault_addr, VmPerms::WRITE))
                .unwrap();
            assert_eq!(vmar.get_rss_counter(RssType::Anon), 1);
            {
                let guard = disable_preempt();
                let mut cursor = vmar.vm_space.cursor_mut(&guard, &range).unwrap();
                assert!(
                    matches!(cursor.aux_meta().inner.find_one(&fault_addr), Some(PteRangeMeta::ChildPt(child)) if *child == (2 * unit..3 * unit))
                );
                for outside in [unit..2 * unit, 3 * unit..4 * unit] {
                    let Some(PteRangeMeta::VmMapping(mapping)) =
                        cursor.aux_meta().inner.find_one(&outside.start)
                    else {
                        panic!("outside mapping fragment lost during delegation");
                    };
                    assert_eq!(mapping.range(), outside);
                    assert_eq!(mapping.frames_mapped(), Some(0));
                    assert!(mapping.perms().contains(perms));
                    assert!(matches!(mapping.mapped_mem(), MappedMemory::Anonymous));
                }
                cursor.jump(fault_addr).unwrap();
                while cursor.push_level_if_exists().is_some() {}
                assert_eq!(cursor.level(), 1);
                let Some(PteRangeMeta::VmMapping(mapping)) =
                    cursor.aux_meta().inner.find_one(&fault_addr)
                else {
                    panic!("faulted leaf must own the delegated mapping");
                };
                assert_eq!(mapping.range(), fault_addr..fault_addr + page_size_at(2));
                assert_eq!(mapping.frames_mapped(), Some(1));
                assert!(mapping.perms().contains(perms));
                assert!(matches!(mapping.mapped_mem(), MappedMemory::Anonymous));
                assert!(
                    matches!(cursor.query(), VmQueriedItem::MappedRam { prop, .. } if prop.flags.contains(PageFlags::RW | PageFlags::ACCESSED | PageFlags::DIRTY))
                );
            }
        }
    }

    #[ktest]
    fn fault_cursor_respects_adjacent_permissions_across_leaf_boundary() {
        let vmar = new_vmar();
        let boundary = 2 * page_size_at(2);
        let left = boundary - PAGE_SIZE;
        map_anon(&vmar, left..boundary, VmPerms::READ | VmPerms::WRITE);
        map_anon(&vmar, boundary..boundary + PAGE_SIZE, VmPerms::READ);
        vmar.handle_page_fault(&PageFaultInfo::new(left, VmPerms::WRITE))
            .unwrap();
        assert!(
            vmar.handle_page_fault(&PageFaultInfo::new(boundary, VmPerms::WRITE))
                .is_err()
        );
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 1);
        vmar.handle_page_fault(&PageFaultInfo::new(boundary, VmPerms::READ))
            .unwrap();
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 2);
        let guard = disable_preempt();
        let mut cursor = vmar
            .vm_space
            .cursor_mut_base_pages(&guard, &(boundary..boundary + page_size_at(2)))
            .unwrap();
        assert_eq!(cursor.guard_level(), 1);
        assert!(
            matches!(cursor.query(), VmQueriedItem::MappedRam { prop, .. } if prop.flags.contains(PageFlags::R) && !prop.flags.contains(PageFlags::W))
        );
    }

    #[ktest]
    fn vacant_anonymous_leaf_keeps_permissions_and_counts_only_new_pages() {
        let vmar = new_vmar();
        let base = page_size_at(2);
        let split = base + 3 * PAGE_SIZE;
        let end = split + PAGE_SIZE;
        map_anon(&vmar, base..split, VmPerms::READ | VmPerms::WRITE);
        map_anon(&vmar, split..end, VmPerms::READ);
        let fault = |addr, perms| vmar.handle_page_fault(&PageFaultInfo::new(addr, perms));
        fault(base, VmPerms::READ).unwrap();
        fault(base + PAGE_SIZE + 7, VmPerms::WRITE).unwrap();
        fault(base + PAGE_SIZE + 7, VmPerms::WRITE).unwrap();
        assert_eq!(
            fault(split, VmPerms::WRITE).unwrap_err().error(),
            Errno::EACCES
        );
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 2);
        fault(split, VmPerms::READ).unwrap();
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 3);
        let guard = disable_preempt();
        let mut cursor = vmar
            .vm_space
            .cursor_mut_base_pages(&guard, &(base..end))
            .unwrap();
        cursor.jump(base + PAGE_SIZE).unwrap();
        assert!(
            matches!(cursor.query(), VmQueriedItem::MappedRam { prop, .. }
            if prop.flags.contains(PageFlags::RW | PageFlags::ACCESSED | PageFlags::DIRTY))
        );
        cursor.jump(base + 2 * PAGE_SIZE).unwrap();
        assert!(matches!(cursor.query(), VmQueriedItem::None));
        cursor.jump(split).unwrap();
        assert!(
            matches!(cursor.query(), VmQueriedItem::MappedRam { prop, .. }
            if prop.flags.contains(PageFlags::R | PageFlags::ACCESSED)
                && !prop.flags.intersects(PageFlags::W | PageFlags::DIRTY))
        );
    }

    #[ktest]
    fn unmap_near_leaf_edge_preserves_neighbor_and_resident_accounting() {
        let vmar = new_vmar();
        let span = page_size_at(2);
        let base = 8 * span;
        let end = base + 4 * span;
        let rw = VmPerms::READ | VmPerms::WRITE;
        map_anon(&vmar, base..end, rw);
        let addr = base + 2 * span - 2 * PAGE_SIZE;
        vmar.remove_mapping(addr..addr + PAGE_SIZE).unwrap();
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 0);
        {
            let guard = disable_preempt();
            let mut cursor = vmar.vm_space.cursor_mut(&guard, &(base..end)).unwrap();
            cursor.jump(base + 2 * span).unwrap();
            cursor.adjust_level(2);
            assert!(matches!(cursor.aux_meta().inner.find_one(&(base + 2 * span)), Some(PteRangeMeta::ChildPt(_))));
        }
        assert!(vmar.handle_page_fault(&PageFaultInfo::new(addr, VmPerms::WRITE)).is_err());
        for va in [addr - PAGE_SIZE, addr + PAGE_SIZE, base + 2 * span] {
            vmar.handle_page_fault(&PageFaultInfo::new(va, VmPerms::WRITE)).unwrap();
        }
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 3);
        vmar.remove_mapping(base..end).unwrap();
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 0);
    }

    #[ktest]
    fn fault_near_leaf_edge_keeps_adjacent_table_unprepared() {
        let span = page_size_at(2);
        let base = 8 * span;
        let rw = VmPerms::READ | VmPerms::WRITE;
        for includes_neighbor in [false, true] {
            let vmar = new_vmar();
            let end = base + if includes_neighbor { 4 * span } else { 2 * span };
            map_anon(&vmar, base..end, rw);
            let boundary = base + 2 * span;
            let edge = boundary - 3 * PAGE_SIZE;
            vmar.handle_page_fault(&PageFaultInfo::new(edge, VmPerms::WRITE)).unwrap();
            assert_eq!(vmar.get_rss_counter(RssType::Anon), 1);
            {
                let guard = disable_preempt();
                let mut cursor = vmar.vm_space.cursor_mut(&guard, &(base..base + 4 * span)).unwrap();
                cursor.jump(boundary).unwrap();
                cursor.adjust_level(2);
                assert_eq!(matches!(cursor.aux_meta().inner.find_one(&boundary),
                    Some(PteRangeMeta::ChildPt(_))), false);
            }
            let crossed = vmar.handle_page_fault(&PageFaultInfo::new(boundary, VmPerms::WRITE));
            assert_eq!(crossed.is_ok(), includes_neighbor);
            assert_eq!(vmar.get_rss_counter(RssType::Anon), if includes_neighbor { 2 } else { 1 });
            vmar.remove_mapping(base..end).unwrap();
            assert_eq!(vmar.get_rss_counter(RssType::Anon), 0);
        }
    }

    #[ktest]
    fn fault_cursor_preserves_forced_permission_rules() {
        let vmar = new_vmar();
        let addr = page_size_at(2);
        map_anon(&vmar, addr..addr + PAGE_SIZE, VmPerms::empty());
        assert!(
            vmar.handle_page_fault(&PageFaultInfo::new(addr, VmPerms::READ))
                .is_err()
        );
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 0);
        vmar.handle_page_fault(&PageFaultInfo::new(addr, VmPerms::READ).force())
            .unwrap();
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 1);
        let guard = disable_preempt();
        let mut cursor = vmar
            .vm_space
            .cursor_mut_base_pages(&guard, &(addr..addr + page_size_at(2)))
            .unwrap();
        assert!(
            matches!(cursor.query(), VmQueriedItem::MappedRam { prop, .. } if !prop.flags.intersects(PageFlags::RW))
        );
    }

    #[derive(Debug)]
    struct FaultDevice;

    impl MappedObject for FaultDevice {
        fn dup_at_offset(&self, _offset: usize) -> Box<dyn MappedObject> {
            Box::new(Self)
        }
    }

    #[ktest]
    fn device_fault_fallback_maps_iomem_as_base_pages() {
        use ostd::io::IoMem;

        use crate::vm::vmar::vmar_impls::{
            VmarSpace,
            map::{MmapMode, map_to_page_table},
        };

        let space = VmarSpace::new();
        let size = page_size_at(2);
        let range = size..2 * size;
        let perms = VmPerms::READ | VmPerms::WRITE;
        let mapping = VmMapping::new(
            NonZeroUsize::new(size).unwrap(),
            range.start,
            MappedMemory::Device(Arc::new(FaultDevice)),
            None,
            MmapMode::Shared,
            false,
            perms,
        );
        let guard = disable_preempt();
        {
            let mut cursor = space.cursor_mut(&guard, &range).unwrap();
            map_to_page_table(&mut cursor, mapping);
        }
        // This is the cursor and helper used after the device callback retries.
        let mut cursor = space.cursor_mut_base_pages(&guard, &range).unwrap();
        assert_eq!(cursor.guard_level(), 1);
        const IO_START: usize = 0x300_000_000_000;
        let io_mem = IoMem::acquire(IO_START..IO_START + size).unwrap();
        let frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let mut pages = Vec::new();
        let mut handle = MapHandle::new(size, &mut pages);
        handle.map_frame(0, frame.into());
        handle.map_iomem(PAGE_SIZE, io_mem.slice(PAGE_SIZE..size));
        assert_eq!(map_device_pages(&mut cursor, &range, perms, pages), 1);
        for offset in (PAGE_SIZE..size).step_by(PAGE_SIZE) {
            cursor.jump(range.start + offset).unwrap();
            assert!(
                matches!(cursor.query(), VmQueriedItem::MappedIoMem { paddr, level: 1, prop } if paddr == IO_START + offset && prop.flags.contains(PageFlags::RW))
            );
        }
        let Some(PteRangeMeta::VmMapping(mapping)) = cursor.aux_meta().inner.find_one(&range.start)
        else {
            panic!("device mapping must remain owned by the leaf");
        };
        assert_eq!(mapping.frames_mapped(), Some(1));
        assert_eq!(mapping.range(), range);
    }
}
