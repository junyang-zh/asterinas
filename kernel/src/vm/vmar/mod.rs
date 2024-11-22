// SPDX-License-Identifier: MPL-2.0

//! Virtual Memory Address Regions (VMARs).

mod dyn_cap;
mod interval_set;
mod static_cap;
pub mod vm_mapping;

use core::{
    num::NonZeroUsize,
    ops::Range,
    sync::atomic::{AtomicU32, Ordering},
};

use align_ext::AlignExt;
use aster_rights::Rights;
use ostd::{
    cpu::CpuExceptionInfo,
    mm::{
        tlb::TlbFlushOp,
        vm_space::{Token, VmItem},
        CachePolicy, FrameAllocOptions, PageFlags, PageProperty, VmSpace, MAX_USERSPACE_VADDR,
    },
};
use vm_mapping::{VmMarker, VmoBackedVMA};

use self::{
    interval_set::{Interval, IntervalSet},
    vm_mapping::{MappedVmo, VmMapping},
};
use super::page_fault_handler::PageFaultHandler;
use crate::{
    prelude::*,
    thread::exception::{handle_page_fault_from_vm_space, PageFaultInfo},
    vm::{
        perms::VmPerms,
        util::duplicate_frame,
        vmo::{Vmo, VmoRightsOp},
    },
};

/// Virtual Memory Address Regions (VMARs) are a type of capability that manages
/// user address spaces.
///
/// # Capabilities
///
/// As a capability, each VMAR is associated with a set of access rights,
/// whose semantics are explained below.
///
/// The semantics of each access rights for VMARs are described below:
///  * The Dup right allows duplicating a VMAR.
///  * The Read, Write, Exec rights allow creating memory mappings with
///    readable, writable, and executable access permissions, respectively.
///  * The Read and Write rights allow the VMAR to be read from and written to
///    directly.
///
/// VMARs are implemented with two flavors of capabilities:
/// the dynamic one (`Vmar<Rights>`) and the static one (`Vmar<R: TRights>`).
pub struct Vmar<R = Rights>(Arc<Vmar_>, R);

pub trait VmarRightsOp {
    /// Returns the access rights.
    fn rights(&self) -> Rights;
    /// Checks whether current rights meet the input `rights`.
    fn check_rights(&self, rights: Rights) -> Result<()>;
}

impl<R> PartialEq for Vmar<R> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<R> VmarRightsOp for Vmar<R> {
    default fn rights(&self) -> Rights {
        unimplemented!()
    }

    default fn check_rights(&self, rights: Rights) -> Result<()> {
        if self.rights().contains(rights) {
            Ok(())
        } else {
            return_errno_with_message!(Errno::EACCES, "Rights check failed");
        }
    }
}

impl<R> PageFaultHandler for Vmar<R> {
    default fn handle_page_fault(&self, _page_fault_info: &PageFaultInfo) -> Result<()> {
        unimplemented!()
    }
}

impl<R> Vmar<R> {
    /// FIXME: This function should require access control
    pub fn vm_space(&self) -> &Arc<VmSpace> {
        self.0.vm_space()
    }

    /// Resizes the original mapping.
    ///
    /// The range of the mapping goes from `map_addr..map_addr + old_size` to
    /// `map_addr..map_addr + new_size`.
    ///
    /// The range of the original mapping does not have to solely map to a
    /// whole [`VmMapping`], but it must ensure that all existing ranges have a
    /// mapping. Otherwise, this method will return `Err`.
    ///
    /// If the new mapping size is smaller than the original mapping size, the
    /// extra part will be unmapped. If the new mapping is larger than the old
    /// mapping and the extra part overlaps with existing mapping, resizing
    /// will fail and return `Err`.
    pub fn resize_mapping(&self, map_addr: Vaddr, old_size: usize, new_size: usize) -> Result<()> {
        self.0.resize_mapping(map_addr, old_size, new_size)
    }

    fn alloc_vmo_backed_id(&self) -> u32 {
        self.0.vmo_backed_id_alloc.fetch_add(1, Ordering::Relaxed)
    }
}

pub(super) struct Vmar_ {
    /// VMAR inner
    inner: RwMutex<VmarInner>,
    /// The offset relative to the root VMAR
    base: Vaddr,
    /// The total size of the VMAR in bytes
    size: usize,
    /// The attached `VmSpace`
    vm_space: Arc<VmSpace>,
    vmo_backed_id_alloc: AtomicU32,
}

struct VmarInner {
    /// The mapped pages and associated metadata.
    vm_mappings: IntervalSet<Vaddr, VmMapping>,
    /// The map from the VMO-backed ID to the VMA structure.
    vma_map: BTreeMap<u32, VmoBackedVMA>,
}

impl VmarInner {
    const fn new() -> Self {
        Self {
            vm_mappings: IntervalSet::new(),
            vma_map: BTreeMap::new(),
        }
    }

    /// Allocates a free region for mapping with a specific offset and size.
    ///
    /// If the provided range is already occupied, return an error.
    fn alloc_free_region_exact(&mut self, offset: Vaddr, size: usize) -> Result<Range<Vaddr>> {
        if self
            .vm_mappings
            .find(&(offset..offset + size))
            .next()
            .is_some()
        {
            return_errno_with_message!(Errno::EACCES, "Requested region is already occupied");
        }

        Ok(offset..(offset + size))
    }

    /// Allocates a free region for mapping with a specific offset and size.
    ///
    /// If the provided range is already occupied, this function truncates all
    /// the mappings that intersect with the range.
    fn alloc_free_region_exact_truncate(
        &mut self,
        vm_space: &VmSpace,
        offset: Vaddr,
        size: usize,
    ) -> Result<Range<Vaddr>> {
        let range = offset..offset + size;
        let mut mappings_to_remove = Vec::new();
        for vm_mapping in self.vm_mappings.find(&range) {
            mappings_to_remove.push(vm_mapping.map_to_addr());
        }

        for vm_mapping_addr in mappings_to_remove {
            let vm_mapping = self.vm_mappings.remove(&vm_mapping_addr).unwrap();
            let vm_mapping_range = vm_mapping.range();
            let intersected_range = get_intersected_range(&range, &vm_mapping_range);

            let (left, taken, right) = vm_mapping.split_range(&intersected_range)?;
            if let Some(left) = left {
                self.vm_mappings.insert(left);
            }
            if let Some(right) = right {
                self.vm_mappings.insert(right);
            }

            taken.unmap(vm_space)?;
        }

        Ok(offset..(offset + size))
    }

    /// Allocates a free region for mapping.
    ///
    /// If no such region is found, return an error.
    fn alloc_free_region(&mut self, size: usize, align: usize) -> Result<Range<Vaddr>> {
        // Fast path that there's still room to the end.
        let highest_occupied = self
            .vm_mappings
            .iter()
            .next_back()
            .map_or(ROOT_VMAR_LOWEST_ADDR, |vm_mapping| vm_mapping.range().end);
        // FIXME: The up-align may overflow.
        let last_occupied_aligned = highest_occupied.align_up(align);
        if let Some(last) = last_occupied_aligned.checked_add(size) {
            if last <= ROOT_VMAR_CAP_ADDR {
                return Ok(last_occupied_aligned..last);
            }
        }

        // Slow path that we need to search for a free region.
        // Here, we use a simple brute-force FIRST-FIT algorithm.
        // Allocate as low as possible to reduce fragmentation.
        let mut last_end: Vaddr = ROOT_VMAR_LOWEST_ADDR;
        for vm_mapping in self.vm_mappings.iter() {
            let range = vm_mapping.range();

            debug_assert!(range.start >= last_end);
            debug_assert!(range.end <= highest_occupied);

            let last_aligned = last_end.align_up(align);
            let needed_end = last_aligned
                .checked_add(size)
                .ok_or(Error::new(Errno::ENOMEM))?;

            if needed_end <= range.start {
                return Ok(last_aligned..needed_end);
            }

            last_end = range.end;
        }

        return_errno_with_message!(Errno::ENOMEM, "Cannot find free region for mapping");
    }
}

pub const ROOT_VMAR_LOWEST_ADDR: Vaddr = 0x001_0000; // 64 KiB is the Linux configurable default
const ROOT_VMAR_CAP_ADDR: Vaddr = MAX_USERSPACE_VADDR;

/// Returns whether the input `vaddr` is a legal user space virtual address.
pub fn is_userspace_vaddr(vaddr: Vaddr) -> bool {
    (ROOT_VMAR_LOWEST_ADDR..ROOT_VMAR_CAP_ADDR).contains(&vaddr)
}

impl Interval<usize> for Arc<Vmar_> {
    fn range(&self) -> Range<usize> {
        self.base..(self.base + self.size)
    }
}

impl Vmar_ {
    fn new(inner: VmarInner, vm_space: Arc<VmSpace>, base: usize, size: usize) -> Arc<Self> {
        Arc::new(Vmar_ {
            inner: RwMutex::new(inner),
            base,
            size,
            vm_space,
            vmo_backed_id_alloc: AtomicU32::new(1),
        })
    }

    fn new_root() -> Arc<Self> {
        let vmar_inner = VmarInner {
            vm_mappings: IntervalSet::new(),
            vma_map: BTreeMap::new(),
        };
        let mut vm_space = VmSpace::new();
        vm_space.register_page_fault_handler(handle_page_fault_wrapper);
        Vmar_::new(vmar_inner, Arc::new(vm_space), 0, ROOT_VMAR_CAP_ADDR)
    }

    fn protect(&self, perms: VmPerms, range: Range<usize>) -> Result<()> {
        assert!(range.start % PAGE_SIZE == 0);
        assert!(range.end % PAGE_SIZE == 0);
        self.do_protect_inner(perms, range)?;
        Ok(())
    }

    // Do real protect. The protected range is ensured to be mapped.
    fn do_protect_inner(&self, perms: VmPerms, range: Range<usize>) -> Result<()> {
        let mut inner = self.inner.write();
        let vm_space = self.vm_space();

        let mut protect_mappings = Vec::new();

        for vm_mapping in inner.vm_mappings.find(&range) {
            protect_mappings.push((vm_mapping.map_to_addr(), vm_mapping.perms()));
        }

        for (vm_mapping_addr, vm_mapping_perms) in protect_mappings {
            if perms == vm_mapping_perms {
                continue;
            }
            let vm_mapping = inner.vm_mappings.remove(&vm_mapping_addr).unwrap();
            let vm_mapping_range = vm_mapping.range();
            let intersected_range = get_intersected_range(&range, &vm_mapping_range);

            // Protects part of the taken `VmMapping`.
            let (left, taken, right) = vm_mapping.split_range(&intersected_range)?;

            let taken = taken.protect(vm_space.as_ref(), perms);
            inner.vm_mappings.insert(taken);

            // And put the rest back.
            if let Some(left) = left {
                inner.vm_mappings.insert(left);
            }
            if let Some(right) = right {
                inner.vm_mappings.insert(right);
            }
        }

        Ok(())
    }

    /// Handles user space page fault, if the page fault is successfully handled, return Ok(()).
    pub fn handle_page_fault(&self, page_fault_info: &PageFaultInfo) -> Result<()> {
        let address = page_fault_info.address;

        if !(self.base..self.base + self.size).contains(&address) {
            return_errno_with_message!(Errno::EACCES, "page fault address is not in current VMAR");
        }

        let page_aligned_addr = address.align_down(PAGE_SIZE);
        let is_write_fault = page_fault_info.required_perms.contains(VmPerms::WRITE);
        let is_exec_fault = page_fault_info.required_perms.contains(VmPerms::EXEC);

        let mut cursor = self
            .vm_space
            .cursor_mut(&(page_aligned_addr..page_aligned_addr + PAGE_SIZE))?;

        match cursor.query().unwrap() {
            VmItem::Marked {
                va: _,
                len: _,
                token,
            } => {
                let marker = VmMarker::decode(token);

                if !marker.perms.contains(page_fault_info.required_perms) {
                    trace!(
                        "self.perms {:?}, page_fault_info.required_perms {:?}",
                        marker.perms,
                        page_fault_info.required_perms,
                    );
                    return_errno_with_message!(Errno::EACCES, "perm check fails");
                }

                if let Some(vmo_backed_id) = marker.vmo_backed_id {
                    // On-demand VMO-backed mapping.
                    //
                    // It includes file-backed mapping and shared anonymous mapping.

                    let vmar_inner = self.inner.read();
                    let id_map = &vmar_inner.vma_map;
                    let vmo_backed_vma = id_map.get(&vmo_backed_id).unwrap();
                    let vmo = &vmo_backed_vma.vmo;

                    let (frame, need_cow) = {
                        let page_offset =
                            address.align_down(PAGE_SIZE) - vmo_backed_vma.map_to_addr;
                        if let Ok(frame) = vmo.get_committed_frame(page_offset) {
                            if !marker.is_shared && is_write_fault {
                                // Write access to private VMO-backed mapping. Performs COW directly.
                                (duplicate_frame(&frame)?, false)
                            } else {
                                // Operations to shared mapping or read access to private VMO-backed mapping.
                                // If read access to private VMO-backed mapping triggers a page fault,
                                // the map should be readonly. If user next tries to write to the frame,
                                // another page fault will be triggered which will performs a COW (Copy-On-Write).
                                (frame, !marker.is_shared)
                            }
                        } else {
                            if !marker.is_shared {
                                // The page index is outside the VMO. This is only allowed in private mapping.
                                (FrameAllocOptions::new(1).alloc_single()?, false)
                            } else {
                                return_errno_with_message!(
                                    Errno::EFAULT,
                                    "could not find a corresponding physical page"
                                );
                            }
                        }
                    };

                    let mut page_flags = marker.perms.into();

                    if need_cow {
                        page_flags -= PageFlags::W;
                        page_flags |= PageFlags::AVAIL1;
                    }

                    if marker.is_shared {
                        page_flags |= PageFlags::AVAIL2;
                    }

                    // Pre-fill A/D bits to avoid A/D TLB miss.
                    page_flags |= PageFlags::ACCESSED;
                    if is_write_fault {
                        page_flags |= PageFlags::DIRTY;
                    }
                    let map_prop = PageProperty::new(page_flags, CachePolicy::Writeback);

                    cursor.map(frame, map_prop);
                } else {
                    // On-demand non-vmo-backed mapping.
                    //
                    // It is a private anonymous mapping.

                    let vm_perms = marker.perms;

                    let mut page_flags = vm_perms.into();

                    if marker.is_shared {
                        page_flags |= PageFlags::AVAIL2;
                        unimplemented!("shared non-vmo-backed mapping");
                    }

                    // Pre-fill A/D bits to avoid A/D TLB miss.
                    page_flags |= PageFlags::ACCESSED;
                    if is_write_fault {
                        page_flags |= PageFlags::DIRTY;
                    }

                    let map_prop = PageProperty::new(page_flags, CachePolicy::Writeback);

                    cursor.map(FrameAllocOptions::new(1).alloc_single()?, map_prop);
                }
            }
            VmItem::Mapped {
                va,
                frame,
                mut prop,
            } => {
                if VmPerms::from(prop.flags).contains(page_fault_info.required_perms) {
                    // The page fault is already handled maybe by other threads.
                    // Just flush the TLB and return.
                    TlbFlushOp::Address(va).perform_on_current();
                    return Ok(());
                }

                if is_exec_fault {
                    return_errno_with_message!(
                        Errno::EACCES,
                        "page fault at non-executable mapping"
                    );
                }

                let is_cow = prop.flags.contains(PageFlags::AVAIL1);
                let is_shared = prop.flags.contains(PageFlags::AVAIL2);

                if !is_cow && is_write_fault {
                    return_errno_with_message!(Errno::EACCES, "page fault at read-only mapping");
                }

                // Perform COW if it is a write access to a shared mapping.

                // If the forked child or parent immediately unmaps the page after
                // the fork without accessing it, we are the only reference to the
                // frame. We can directly map the frame as writable without
                // copying. In this case, the reference count of the frame is 2 (
                // one for the mapping and one for the frame handle itself).
                let only_reference = frame.reference_count() == 2;

                let additional_flags = PageFlags::W | PageFlags::ACCESSED | PageFlags::DIRTY;

                if is_shared || only_reference {
                    cursor.protect_next(
                        PAGE_SIZE,
                        &mut |p: &mut PageProperty| {
                            p.flags |= additional_flags;
                            p.flags -= PageFlags::AVAIL1; // Remove COW flag
                        },
                        &mut |_: &mut Token| {},
                    );
                    cursor.flusher().issue_tlb_flush(TlbFlushOp::Address(va));
                    cursor.flusher().dispatch_tlb_flush();
                } else {
                    let new_frame = duplicate_frame(&frame)?;
                    prop.flags |= additional_flags;
                    cursor.map(new_frame, prop);
                }
            }
            VmItem::NotMapped { .. } => {
                return_errno_with_message!(Errno::EACCES, "page fault at an address not mapped");
            }
        }

        Ok(())
    }

    /// Clears all content of the root VMAR.
    fn clear_root_vmar(&self) -> Result<()> {
        self.vm_space.clear().unwrap();
        let mut inner = self.inner.write();
        inner.vm_mappings.clear();
        Ok(())
    }

    pub fn remove_mapping(&self, range: Range<usize>) -> Result<()> {
        let mut inner = self.inner.write();
        inner.alloc_free_region_exact_truncate(&self.vm_space, range.start, range.len())?;
        Ok(())
    }

    // Split and unmap the found mapping if resize smaller.
    // Enlarge the last mapping if resize larger.
    fn resize_mapping(&self, map_addr: Vaddr, old_size: usize, new_size: usize) -> Result<()> {
        debug_assert!(map_addr % PAGE_SIZE == 0);
        debug_assert!(old_size % PAGE_SIZE == 0);
        debug_assert!(new_size % PAGE_SIZE == 0);

        if new_size == 0 {
            return_errno_with_message!(Errno::EINVAL, "can not resize a mapping to 0 size");
        }

        if new_size == old_size {
            return Ok(());
        }

        let old_map_end = map_addr + old_size;
        let new_map_end = map_addr + new_size;

        if new_size < old_size {
            self.remove_mapping(new_map_end..old_map_end)?;
            return Ok(());
        }

        let mut inner = self.inner.write();
        let last_mapping = inner.vm_mappings.find_one(&(old_map_end - 1)).unwrap();
        let last_mapping_addr = last_mapping.map_to_addr();
        let last_mapping = inner.vm_mappings.remove(&last_mapping_addr).unwrap();

        let extra_mapping_start = last_mapping.map_end();
        inner.alloc_free_region_exact(extra_mapping_start, new_map_end - extra_mapping_start)?;
        let last_mapping = last_mapping.enlarge(self.vm_space(), new_map_end - extra_mapping_start);
        inner.vm_mappings.insert(last_mapping);
        Ok(())
    }

    /// Returns the attached `VmSpace`.
    fn vm_space(&self) -> &Arc<VmSpace> {
        &self.vm_space
    }

    pub(super) fn new_fork_root(self: &Arc<Self>) -> Result<Arc<Self>> {
        let new_vmar_ = {
            let vmar_inner = VmarInner::new();
            let mut new_space = VmSpace::new();
            new_space.register_page_fault_handler(handle_page_fault_wrapper);
            Vmar_::new(vmar_inner, Arc::new(new_space), self.base, self.size)
        };

        {
            let inner = self.inner.read();
            let mut new_inner = new_vmar_.inner.write();

            // Clone mappings.
            let new_vmspace = new_vmar_.vm_space();
            let range = self.base..(self.base + self.size);
            let mut new_cursor = new_vmspace.cursor_mut(&range).unwrap();
            let cur_vmspace = self.vm_space();
            let mut cur_cursor = cur_vmspace.cursor_mut(&range).unwrap();
            for vm_mapping in inner.vm_mappings.iter() {
                let base = vm_mapping.map_to_addr();

                // Clone the `VmMapping` to the new VMAR.
                let new_mapping = vm_mapping.new_fork()?;
                new_inner.vm_mappings.insert(new_mapping);

                // Protect the mapping and copy to the new page table for COW.
                cur_cursor.jump(base).unwrap();
                new_cursor.jump(base).unwrap();
                let mut prot_op = |page: &mut PageProperty| {
                    if page.flags.contains(PageFlags::W) {
                        page.flags |= PageFlags::AVAIL1; // Copy-on-write
                    }
                    page.flags -= PageFlags::W;
                };
                let mut token_op = |token: &mut Token| {
                    let marker = VmMarker::decode(*token);
                    if let Some(vmo_backed_id) = marker.vmo_backed_id {
                        if !new_inner.vma_map.contains_key(&vmo_backed_id) {
                            let vma = inner.vma_map.get(&vmo_backed_id).unwrap();
                            new_inner.vma_map.insert(vmo_backed_id, vma.clone());
                        }
                    }
                };
                new_cursor.copy_from(
                    &mut cur_cursor,
                    vm_mapping.map_size(),
                    &mut prot_op,
                    &mut token_op,
                );
            }
            cur_cursor.flusher().issue_tlb_flush(TlbFlushOp::All);
            cur_cursor.flusher().dispatch_tlb_flush();
        }

        Ok(new_vmar_)
    }
}

/// This is for fallible user space write handling.
fn handle_page_fault_wrapper(
    vm_space: &VmSpace,
    trap_info: &CpuExceptionInfo,
) -> core::result::Result<(), ()> {
    handle_page_fault_from_vm_space(vm_space, &trap_info.try_into().unwrap())
}

impl<R> Vmar<R> {
    /// The base address, i.e., the offset relative to the root VMAR.
    ///
    /// The base address of a root VMAR is zero.
    pub fn base(&self) -> Vaddr {
        self.0.base
    }

    /// The size of the VMAR in bytes.
    pub fn size(&self) -> usize {
        self.0.size
    }
}

/// Options for creating a new mapping. The mapping is not allowed to overlap
/// with any child VMARs. And unless specified otherwise, it is not allowed
/// to overlap with any existing mapping, either.
pub struct VmarMapOptions<R1, R2> {
    parent: Vmar<R1>,
    vmo: Option<Vmo<R2>>,
    perms: VmPerms,
    vmo_offset: usize,
    vmo_limit: usize,
    size: usize,
    offset: Option<usize>,
    align: usize,
    can_overwrite: bool,
    // Whether the mapping is mapped with `MAP_SHARED`
    is_shared: bool,
    // Whether the mapping needs to handle surrounding pages when handling page fault.
    handle_page_faults_around: bool,
}

impl<R1, R2> VmarMapOptions<R1, R2> {
    /// Creates a default set of options with the VMO and the memory access
    /// permissions.
    ///
    /// The VMO must have access rights that correspond to the memory
    /// access permissions. For example, if `perms` contains `VmPerms::Write`,
    /// then `vmo.rights()` should contain `Rights::WRITE`.
    pub fn new(parent: Vmar<R1>, size: usize, perms: VmPerms) -> Self {
        Self {
            parent,
            vmo: None,
            perms,
            vmo_offset: 0,
            vmo_limit: usize::MAX,
            size,
            offset: None,
            align: PAGE_SIZE,
            can_overwrite: false,
            is_shared: false,
            handle_page_faults_around: false,
        }
    }

    /// Binds a VMO to the mapping.
    ///
    /// If the mapping is a private mapping, its size may not be equal to that of the VMO.
    /// For example, it is ok to create a mapping whose size is larger than
    /// that of the VMO, although one cannot read from or write to the
    /// part of the mapping that is not backed by the VMO.
    ///
    /// So you may wonder: what is the point of supporting such _oversized_
    /// mappings?  The reason is two-fold.
    ///  1. VMOs are resizable. So even if a mapping is backed by a VMO whose
    ///     size is equal to that of the mapping initially, we cannot prevent
    ///     the VMO from shrinking.
    ///  2. Mappings are not allowed to overlap by default. As a result,
    ///     oversized mappings can serve as a placeholder to prevent future
    ///     mappings from occupying some particular address ranges accidentally.
    pub fn vmo(mut self, vmo: Vmo<R2>) -> Self {
        self.vmo = Some(vmo);

        self
    }

    /// Sets the offset of the first memory page in the VMO that is to be
    /// mapped into the VMAR.
    ///
    /// The offset must be page-aligned and within the VMO.
    ///
    /// The default value is zero.
    pub fn vmo_offset(mut self, offset: usize) -> Self {
        self.vmo_offset = offset;
        self
    }

    /// Sets the access limit offset for the binding VMO.
    pub fn vmo_limit(mut self, limit: usize) -> Self {
        self.vmo_limit = limit;
        self
    }

    /// Sets the mapping's alignment.
    ///
    /// The default value is the page size.
    ///
    /// The provided alignment must be a power of two and a multiple of the
    /// page size.
    pub fn align(mut self, align: usize) -> Self {
        self.align = align;
        self
    }

    /// Sets the mapping's offset inside the VMAR.
    ///
    /// The offset must satisfy the alignment requirement.
    /// Also, the mapping's range `[offset, offset + size)` must be within
    /// the VMAR.
    ///
    /// If not set, the system will choose an offset automatically.
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Sets whether the mapping can overwrite existing mappings.
    ///
    /// The default value is false.
    ///
    /// If this option is set to true, then the `offset` option must be
    /// set.
    pub fn can_overwrite(mut self, can_overwrite: bool) -> Self {
        self.can_overwrite = can_overwrite;
        self
    }

    /// Sets whether the mapping can be shared with other process.
    ///
    /// The default value is false.
    ///
    /// If this value is set to true, the mapping will be shared with child
    /// process when forking.
    pub fn is_shared(mut self, is_shared: bool) -> Self {
        self.is_shared = is_shared;
        self
    }

    /// Sets the mapping to handle surrounding pages when handling page fault.
    pub fn handle_page_faults_around(mut self) -> Self {
        self.handle_page_faults_around = true;
        self
    }

    /// Creates the mapping and adds it to the parent VMAR.
    ///
    /// All options will be checked at this point.
    ///
    /// On success, the virtual address of the new mapping is returned.
    pub fn build(self) -> Result<Vaddr> {
        self.check_options()?;
        let Self {
            parent,
            vmo,
            perms,
            vmo_offset,
            vmo_limit,
            size: map_size,
            offset,
            align,
            can_overwrite,
            is_shared,
            handle_page_faults_around,
        } = self;

        // Allocates a free region.
        trace!("allocate free region, map_size = 0x{:x}, offset = {:x?}, align = 0x{:x}, can_overwrite = {}", map_size, offset, align, can_overwrite);

        let mut inner = parent.0.inner.write();
        let map_to_addr = if can_overwrite {
            // If can overwrite, the offset is ensured not to be `None`.
            let offset = offset.ok_or(Error::with_message(
                Errno::EINVAL,
                "offset cannot be None since can overwrite is set",
            ))?;
            inner.alloc_free_region_exact_truncate(parent.vm_space(), offset, map_size)?;
            offset
        } else if let Some(offset) = offset {
            inner.alloc_free_region_exact(offset, map_size)?;
            offset
        } else {
            let free_region = inner.alloc_free_region(map_size, align)?;
            free_region.start
        };

        let vmo = vmo.map(|vmo| MappedVmo::new(vmo.to_dyn(), vmo_offset..vmo_limit));

        trace!(
            "build mapping, range = {:#x?}, perms = {:?}, vmo = {:#?}",
            map_to_addr..map_to_addr + map_size,
            perms,
            vmo
        );

        // Build the mapping.
        let vm_mapping = VmMapping::new(
            NonZeroUsize::new(map_size).unwrap(),
            map_to_addr,
            vmo.as_ref().map(|vmo| vmo.dup()).transpose()?,
            is_shared,
            handle_page_faults_around,
            perms,
        );

        // Add the mapping to the VMAR.
        inner.vm_mappings.insert(vm_mapping);

        let mut cursor = parent
            .vm_space()
            .cursor_mut(&(map_to_addr..map_to_addr + map_size))
            .unwrap();

        let marker = VmMarker {
            perms,
            is_shared,
            vmo_backed_id: if let Some(vmo) = vmo {
                let id = parent.alloc_vmo_backed_id();
                let vma = VmoBackedVMA {
                    id,
                    map_size: NonZeroUsize::new(map_size).unwrap(),
                    map_to_addr,
                    vmo,
                    handle_page_faults_around,
                };
                inner.vma_map.insert(id, vma);
                Some(id)
            } else {
                None
            },
        };

        cursor.mark(map_size, marker.encode());

        Ok(map_to_addr)
    }

    /// Checks whether all options are valid.
    fn check_options(&self) -> Result<()> {
        // Check align.
        debug_assert!(self.align % PAGE_SIZE == 0);
        debug_assert!(self.align.is_power_of_two());
        if self.align % PAGE_SIZE != 0 || !self.align.is_power_of_two() {
            return_errno_with_message!(Errno::EINVAL, "invalid align");
        }
        debug_assert!(self.size % self.align == 0);
        if self.size % self.align != 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid mapping size");
        }
        debug_assert!(self.vmo_offset % self.align == 0);
        if self.vmo_offset % self.align != 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid vmo offset");
        }
        if let Some(offset) = self.offset {
            debug_assert!(offset % self.align == 0);
            if offset % self.align != 0 {
                return_errno_with_message!(Errno::EINVAL, "invalid offset");
            }
        }
        self.check_perms()?;
        Ok(())
    }

    /// Checks whether the permissions of the mapping is subset of vmo rights.
    fn check_perms(&self) -> Result<()> {
        let Some(vmo) = &self.vmo else {
            return Ok(());
        };

        let perm_rights = Rights::from(self.perms);
        vmo.check_rights(perm_rights)
    }
}

/// Determines whether two ranges are intersected.
/// returns false if one of the ranges has a length of 0
pub fn is_intersected(range1: &Range<usize>, range2: &Range<usize>) -> bool {
    range1.start.max(range2.start) < range1.end.min(range2.end)
}

/// Gets the intersection range of two ranges.
/// The two ranges should be ensured to be intersected.
pub fn get_intersected_range(range1: &Range<usize>, range2: &Range<usize>) -> Range<usize> {
    debug_assert!(is_intersected(range1, range2));
    range1.start.max(range2.start)..range1.end.min(range2.end)
}
