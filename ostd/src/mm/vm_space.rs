// SPDX-License-Identifier: MPL-2.0

//! Virtual memory space management.
//!
//! The [`VmSpace`] struct is provided to manage the virtual memory space of a
//! user. Cursors are used to traverse and modify over the virtual memory space
//! concurrently. The VM space cursor [`self::Cursor`] is just a wrapper over
//! the page table cursor [`super::page_table::Cursor`], providing efficient,
//! powerful concurrent accesses to the page table, and suffers from the same
//! validity concerns as described in [`super::page_table::cursor`].

use core::{
    ops::{Deref, Range},
    sync::atomic::Ordering,
};

use crate::{
    arch::mm::{tlb_flush_all_excluding_global, PageTableEntry, PagingConsts},
    cpu::{AtomicCpuSet, CpuExceptionInfo, CpuSet, PinCurrentCpu},
    cpu_local_cell,
    mm::{
        kspace::KERNEL_PAGE_TABLE,
        page::DynPage,
        page_table::{self, PageTable, PageTableItem, UserMode},
        tlb::{TlbFlushOp, TlbFlusher, FLUSH_ALL_RANGE_THRESHOLD},
        Frame, PageProperty,
    },
    prelude::*,
    task::{disable_preempt, DisabledPreemptGuard},
};

/// Virtual memory space.
///
/// A virtual memory space (`VmSpace`) can be created and assigned to a user
/// space so that the virtual memory of the user space can be manipulated
/// safely. For example,  given an arbitrary user-space pointer, one can read
/// and write the memory location referred to by the user-space pointer without
/// the risk of breaking the memory safety of the kernel space.
///
/// A newly-created `VmSpace` is not backed by any physical memory pages. To
/// provide memory pages for a `VmSpace`, one can allocate and map physical
/// memory ([`Frame`]s) to the `VmSpace` using the cursor.
///
/// A `VmSpace` can also attach a page fault handler, which will be invoked to
/// handle page faults generated from user space.
#[allow(clippy::type_complexity)]
#[derive(Debug)]
pub struct VmSpace {
    pt: PageTable<UserMode>,
    page_fault_handler: Option<fn(&VmSpace, &CpuExceptionInfo) -> core::result::Result<(), ()>>,
    cpus: AtomicCpuSet,
}

impl VmSpace {
    /// Creates a new VM address space.
    pub fn new() -> Self {
        Self {
            pt: KERNEL_PAGE_TABLE.get().unwrap().create_user_page_table(),
            page_fault_handler: None,
            cpus: AtomicCpuSet::new(CpuSet::new_empty()),
        }
    }

    /// Gets an immutable cursor in the virtual address range.
    ///
    /// The cursor behaves like a lock guard, exclusively owning a sub-tree of
    /// the page table, preventing others from creating a cursor in it. So be
    /// sure to drop the cursor as soon as possible.
    ///
    /// The creation of the cursor may block if another cursor having an
    /// overlapping range is alive.
    pub fn cursor(&self, va: &Range<Vaddr>) -> Result<Cursor<'_>> {
        Ok(self.pt.cursor(va).map(Cursor)?)
    }

    /// Gets an mutable cursor in the virtual address range.
    ///
    /// The same as [`Self::cursor`], the cursor behaves like a lock guard,
    /// exclusively owning a sub-tree of the page table, preventing others
    /// from creating a cursor in it. So be sure to drop the cursor as soon as
    /// possible.
    ///
    /// The creation of the cursor may block if another cursor having an
    /// overlapping range is alive. The modification to the mapping by the
    /// cursor may also block or be overridden the mapping of another cursor.
    pub fn cursor_mut(&self, va: &Range<Vaddr>) -> Result<CursorMut<'_, '_>> {
        Ok(self.pt.cursor_mut(va).map(|pt_cursor| CursorMut {
            space: self,
            pt_cursor,
            flusher: TlbFlusher::new(self.cpus.load(), disable_preempt()),
        })?)
    }

    pub(crate) fn handle_page_fault(
        &self,
        info: &CpuExceptionInfo,
    ) -> core::result::Result<(), ()> {
        if let Some(func) = self.page_fault_handler {
            return func(self, info);
        }
        Err(())
    }

    /// Registers the page fault handler in this `VmSpace`.
    pub fn register_page_fault_handler(
        &mut self,
        func: fn(&VmSpace, &CpuExceptionInfo) -> core::result::Result<(), ()>,
    ) {
        self.page_fault_handler = Some(func);
    }
}

impl Default for VmSpace {
    fn default() -> Self {
        Self::new()
    }
}

/// A shared reference to the virtual memory space.
#[derive(Debug)]
pub struct SharedVmSpace(Arc<VmSpace>);

impl SharedVmSpace {
    /// Allow a virtual memory space to be shared.
    pub fn new(vm_space: VmSpace) -> Self {
        Self(Arc::new(vm_space))
    }

    /// Share a virtual memory space.
    pub fn share(&self) -> Self {
        Self(Arc::clone(&self.0))
    }

    /// Clears the user space mappings in the page table.
    ///
    /// # Panics
    ///
    /// This function panics if
    ///  - the virtual memory space is activated on other CPUs currently.
    ///  - this task do not hold the exclusive access to the shared VM space.
    pub fn clear(&mut self) {
        let preempt_guard = disable_preempt();
        let cpus = self.cpus.load();
        let cpu = preempt_guard.current_cpu();
        let cpus_set_is_empty = cpus.is_empty();
        let cpus_set_is_single_self = cpus.count() == 1 && cpus.contains(cpu);
        assert!(cpus_set_is_empty || cpus_set_is_single_self);

        let space =
            Arc::get_mut(&mut self.0).expect("shared virtual memory space cannot be cleared");

        // SAFETY: We checked that no other CPUs are activating the VM
        // space currently. Other CPUs cannot activate after the check because
        // we are exclusively accessed by the current task.
        unsafe { space.pt.clear() };

        tlb_flush_all_excluding_global();
    }

    /// Activates the page table on the current CPU.
    pub(crate) fn activate(&self) {
        let preempt_guard = disable_preempt();
        let cpu = preempt_guard.current_cpu();

        let last_ptr = ACTIVATED_VM_SPACE.load();

        if last_ptr == Arc::as_ptr(&self.0) {
            return;
        }

        // Record ourselves in the CPU set and the activated VM space pointer.
        self.0.cpus.add(cpu, Ordering::Relaxed);
        let self_ptr = Arc::into_raw(Arc::clone(&self.0)) as *mut VmSpace;
        ACTIVATED_VM_SPACE.store(self_ptr);

        if !last_ptr.is_null() {
            // SAFETY: The pointer is cast from an `Arc` when it's activated
            // the last time, so it can be restored and only restored once.
            let last = unsafe { Arc::from_raw(last_ptr) };
            last.cpus.remove(cpu, Ordering::Relaxed);
        }

        self.0.pt.activate();
    }
}

impl Deref for SharedVmSpace {
    type Target = VmSpace;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

/// The cursor for querying over the VM space without modifying it.
///
/// It exclusively owns a sub-tree of the page table, preventing others from
/// reading or modifying the same sub-tree. Two read-only cursors can not be
/// created from the same virtual address range either.
pub struct Cursor<'a>(page_table::Cursor<'a, UserMode, PageTableEntry, PagingConsts>);

impl Iterator for Cursor<'_> {
    type Item = VmItem;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.query();
        if result.is_ok() {
            self.0.move_forward();
        }
        result.ok()
    }
}

impl Cursor<'_> {
    /// Query about the current slot.
    ///
    /// This function won't bring the cursor to the next slot.
    pub fn query(&mut self) -> Result<VmItem> {
        Ok(self.0.query().map(|item| item.try_into().unwrap())?)
    }

    /// Jump to the virtual address.
    pub fn jump(&mut self, va: Vaddr) -> Result<()> {
        self.0.jump(va)?;
        Ok(())
    }

    /// Get the virtual address of the current slot.
    pub fn virt_addr(&self) -> Vaddr {
        self.0.virt_addr()
    }
}

/// The cursor for modifying the mappings in VM space.
///
/// It exclusively owns a sub-tree of the page table, preventing others from
/// reading or modifying the same sub-tree.
pub struct CursorMut<'a, 'b> {
    space: &'a VmSpace,
    pt_cursor: page_table::CursorMut<'b, UserMode, PageTableEntry, PagingConsts>,
    // We have a read lock so the CPU set in the flusher is always a superset
    // of actual activated CPUs.
    flusher: TlbFlusher<DisabledPreemptGuard>,
}

impl CursorMut<'_, '_> {
    /// Query about the current slot.
    ///
    /// This is the same as [`Cursor::query`].
    ///
    /// This function won't bring the cursor to the next slot.
    pub fn query(&mut self) -> Result<VmItem> {
        Ok(self
            .pt_cursor
            .query()
            .map(|item| item.try_into().unwrap())?)
    }

    /// Jump to the virtual address.
    ///
    /// This is the same as [`Cursor::jump`].
    pub fn jump(&mut self, va: Vaddr) -> Result<()> {
        self.pt_cursor.jump(va)?;
        Ok(())
    }

    /// Get the virtual address of the current slot.
    pub fn virt_addr(&self) -> Vaddr {
        self.pt_cursor.virt_addr()
    }

    /// Get the dedicated TLB flusher for this cursor.
    pub fn flusher(&self) -> &TlbFlusher<DisabledPreemptGuard> {
        &self.flusher
    }

    /// Map a frame into the current slot.
    ///
    /// This method will bring the cursor to the next slot after the modification.
    pub fn map(&mut self, frame: Frame, prop: PageProperty) {
        let start_va = self.virt_addr();
        // SAFETY: It is safe to map untyped memory into the userspace.
        let old = unsafe { self.pt_cursor.map(frame.into(), prop) };

        if let Some(old) = old {
            // Load the current cpu set.
            self.flusher.update_cpu(self.space.cpus.load());

            self.flusher
                .issue_tlb_flush_with(TlbFlushOp::Address(start_va), old);
            self.flusher.dispatch_tlb_flush();
        }
    }

    /// Clear the mapping starting from the current slot.
    ///
    /// This method will bring the cursor forward by `len` bytes in the virtual
    /// address space after the modification.
    ///
    /// Already-absent mappings encountered by the cursor will be skipped. It
    /// is valid to unmap a range that is not mapped.
    ///
    /// It must issue and dispatch a TLB flush after the operation. Otherwise,
    /// the memory safety will be compromised. Please call this function less
    /// to avoid the overhead of TLB flush. Using a large `len` is wiser than
    /// splitting the operation into multiple small ones.
    ///
    /// # Panics
    ///
    /// This method will panic if `len` is not page-aligned.
    pub fn unmap(&mut self, len: usize) {
        assert!(len % super::PAGE_SIZE == 0);
        let end_va = self.virt_addr() + len;
        let tlb_prefer_flush_all = len > FLUSH_ALL_RANGE_THRESHOLD;

        let mut vec_tlb_req = Vec::<(usize, DynPage)>::new();
        loop {
            // SAFETY: It is safe to un-map memory in the userspace.
            let result = unsafe { self.pt_cursor.take_next(end_va - self.virt_addr()) };
            match result {
                PageTableItem::Mapped { va, page, .. } => {
                    vec_tlb_req.push((va, page));
                }
                PageTableItem::NotMapped { .. } => {
                    break;
                }
                PageTableItem::MappedUntracked { .. } => {
                    panic!("found untracked memory mapped into `VmSpace`");
                }
            }
        }

        // Load the current cpu set.
        self.flusher.update_cpu(self.space.cpus.load());

        if !self.flusher.need_remote_flush() && tlb_prefer_flush_all {
            self.flusher.issue_tlb_flush(TlbFlushOp::All);
        } else {
            for (va, page) in vec_tlb_req {
                self.flusher
                    .issue_tlb_flush_with(TlbFlushOp::Address(va), page);
            }
        }

        self.flusher.dispatch_tlb_flush();
    }

    /// Applies the operation to the next slot of mapping within the range.
    ///
    /// The range to be found in is the current virtual address with the
    /// provided length.
    ///
    /// The function stops and yields the actually protected range if it has
    /// actually protected a page, no matter if the following pages are also
    /// required to be protected.
    ///
    /// It also makes the cursor moves forward to the next page after the
    /// protected one. If no mapped pages exist in the following range, the
    /// cursor will stop at the end of the range and return [`None`].
    ///
    /// Note that it will **NOT** flush the TLB after the operation. Please
    /// make the decision yourself on when and how to flush the TLB using
    /// [`Self::flusher`].
    ///
    /// # Panics
    ///
    /// This function will panic if:
    ///  - the range to be protected is out of the range where the cursor
    ///    is required to operate;
    ///  - the specified virtual address range only covers a part of a page.
    pub fn protect_next(
        &mut self,
        len: usize,
        mut op: impl FnMut(&mut PageProperty),
    ) -> Option<Range<Vaddr>> {
        // SAFETY: It is safe to protect memory in the userspace.
        unsafe { self.pt_cursor.protect_next(len, &mut op) }
    }

    /// Copies the mapping from the given cursor to the current cursor.
    ///
    /// All the mappings in the current cursor's range must be empty. The
    /// function allows the source cursor to operate on the mapping before
    /// the copy happens. So it is equivalent to protect then duplicate.
    /// Only the mapping is copied, the mapped pages are not copied.
    ///
    /// After the operation, both cursors will advance by the specified length.
    ///
    /// Note that it will **NOT** flush the TLB after the operation. Please
    /// make the decision yourself on when and how to flush the TLB using
    /// the source's [`CursorMut::flusher`].
    ///
    /// # Panics
    ///
    /// This function will panic if:
    ///  - either one of the range to be copied is out of the range where any
    ///    of the cursor is required to operate;
    ///  - either one of the specified virtual address ranges only covers a
    ///    part of a page.
    ///  - the current cursor's range contains mapped pages.
    pub fn copy_from(
        &mut self,
        src: &mut Self,
        len: usize,
        op: &mut impl FnMut(&mut PageProperty),
    ) {
        // SAFETY: Operations on user memory spaces are safe if it doesn't
        // involve dropping any pages.
        unsafe { self.pt_cursor.copy_from(&mut src.pt_cursor, len, op) }
    }
}

cpu_local_cell! {
    /// The `Arc` pointer to the activated VM space on this CPU. If the pointer
    /// is NULL, it means that the activated page table is merely the kernel
    /// page table.
    // TODO: If we are enabling ASID, we need to maintain the TLB state of each
    // CPU, rather than merely the activated `VmSpace`. When ASID is enabled,
    // the non-active `VmSpace`s can still have their TLB entries in the CPU!
    static ACTIVATED_VM_SPACE: *const VmSpace = core::ptr::null();
}

/// The result of a query over the VM space.
#[derive(Debug)]
pub enum VmItem {
    /// The current slot is not mapped.
    NotMapped {
        /// The virtual address of the slot.
        va: Vaddr,
        /// The length of the slot.
        len: usize,
    },
    /// The current slot is mapped.
    Mapped {
        /// The virtual address of the slot.
        va: Vaddr,
        /// The mapped frame.
        frame: Frame,
        /// The property of the slot.
        prop: PageProperty,
    },
}

impl TryFrom<PageTableItem> for VmItem {
    type Error = &'static str;

    fn try_from(item: PageTableItem) -> core::result::Result<Self, Self::Error> {
        match item {
            PageTableItem::NotMapped { va, len } => Ok(VmItem::NotMapped { va, len }),
            PageTableItem::Mapped { va, page, prop } => Ok(VmItem::Mapped {
                va,
                frame: page
                    .try_into()
                    .map_err(|_| "found typed memory mapped into `VmSpace`")?,
                prop,
            }),
            PageTableItem::MappedUntracked { .. } => {
                Err("found untracked memory mapped into `VmSpace`")
            }
        }
    }
}
