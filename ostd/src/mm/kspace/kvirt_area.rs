// SPDX-License-Identifier: MPL-2.0

//! Kernel virtual memory allocation

use core::{
    marker::PhantomData,
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
};

use align_ext::AlignExt;

use super::{KERNEL_PAGE_TABLE, TRACKED_MAPPED_PAGES_RANGE, VMALLOC_VADDR_RANGE};
use crate::{
    mm::{
        page::{meta::PageMeta, DynPage, Page},
        page_prop::PageProperty,
        page_table::PageTableItem,
        Paddr, Vaddr, PAGE_SIZE,
    },
    Error, Result,
};

pub struct KVirtAreaFreeNode {
    block: Range<Vaddr>,
}

impl KVirtAreaFreeNode {
    pub(crate) const fn new(range: Range<Vaddr>) -> Self {
        Self { block: range }
    }
}

pub struct VirtAddrAllocator {
    fullrange: Range<Vaddr>,
    end: AtomicUsize,
}

impl VirtAddrAllocator {
    const fn new(fullrange: Range<Vaddr>) -> Self {
        Self {
            fullrange: fullrange.start..fullrange.end,
            end: AtomicUsize::new(fullrange.start),
        }
    }

    /// Allocates a kernel virtual area.
    ///
    /// This is currently implemented with a simple FIRST-FIT algorithm.
    fn alloc(&self, size: usize) -> Result<Range<Vaddr>> {
        let end = self.end.fetch_add(size, Ordering::AcqRel);
        if end + size > self.fullrange.end {
            return Err(Error::NoMemory);
        }
        Ok(end..end + size)
    }

    /// Frees a kernel virtual area.
    fn free(&self, _range: Range<Vaddr>) {
        // nop
    }
}

static KVIRT_AREA_TRACKED_ALLOCATOR: VirtAddrAllocator =
    VirtAddrAllocator::new(TRACKED_MAPPED_PAGES_RANGE);
static KVIRT_AREA_UNTRACKED_ALLOCATOR: VirtAddrAllocator =
    VirtAddrAllocator::new(VMALLOC_VADDR_RANGE);

#[derive(Debug)]
pub struct Tracked;
#[derive(Debug)]
pub struct Untracked;

pub trait AllocatorSelector {
    fn select_allocator() -> &'static VirtAddrAllocator;
}

impl AllocatorSelector for Tracked {
    fn select_allocator() -> &'static VirtAddrAllocator {
        &KVIRT_AREA_TRACKED_ALLOCATOR
    }
}

impl AllocatorSelector for Untracked {
    fn select_allocator() -> &'static VirtAddrAllocator {
        &KVIRT_AREA_UNTRACKED_ALLOCATOR
    }
}

/// Kernel Virtual Area.
///
/// A tracked kernel virtual area (`KVirtArea<Tracked>`) manages a range of memory in
/// `TRACKED_MAPPED_PAGES_RANGE`. It can map a inner part or all of its virtual memory
/// to some physical tracked pages.
///
/// A untracked kernel virtual area (`KVirtArea<Untracked>`) manages a range of memory in
/// `VMALLOC_VADDR_RANGE`. It can map a inner part or all of its virtual memory to
/// some physical untracked pages.
#[derive(Debug)]
pub struct KVirtArea<M: AllocatorSelector + 'static> {
    range: Range<Vaddr>,
    phantom: PhantomData<M>,
}

impl<M: AllocatorSelector + 'static> KVirtArea<M> {
    pub fn new(size: usize) -> Self {
        let allocator = M::select_allocator();
        let range = allocator.alloc(size).unwrap();
        Self {
            range,
            phantom: PhantomData,
        }
    }

    pub fn start(&self) -> Vaddr {
        self.range.start
    }

    pub fn end(&self) -> Vaddr {
        self.range.end
    }

    pub fn range(&self) -> Range<Vaddr> {
        self.range.start..self.range.end
    }

    pub fn len(&self) -> usize {
        self.range.len()
    }

    fn query_page(&self, addr: Vaddr) -> PageTableItem {
        assert!(self.start() <= addr && self.end() >= addr);
        let start = addr.align_down(PAGE_SIZE);
        let vaddr = start..start + PAGE_SIZE;
        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = page_table.cursor(&vaddr).unwrap();
        cursor.query().unwrap()
    }
}

impl KVirtArea<Tracked> {
    /// Maps pages into the kernel virtual area.
    pub fn map_pages<T: PageMeta>(
        &mut self,
        range: Range<Vaddr>,
        pages: impl Iterator<Item = Page<T>>,
        prop: PageProperty,
    ) {
        assert!(self.start() <= range.start && self.end() >= range.end);
        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = page_table.cursor_mut(&range).unwrap();

        for page in pages.into_iter() {
            // SAFETY: The constructor of the `KVirtArea<Tracked>` structure has already ensured this
            // mapping does not affect kernel's memory safety.
            let _old = unsafe { cursor.map(page.into(), prop) };
        }
    }

    /// Gets the mapped tracked page.
    ///
    /// This function returns None if the address is not mapped (`NotMapped`),
    /// while panics if the address is mapped to a `MappedUntracked` or `PageTableNode` page.
    pub fn get_page(&self, addr: Vaddr) -> Option<DynPage> {
        let query_result = self.query_page(addr);
        match query_result {
            PageTableItem::Mapped {
                va: _,
                page,
                prop: _,
            } => Some(page),
            PageTableItem::NotMapped { .. } => None,
            _ => {
                panic!(
                    "Found '{:?}' mapped into tracked `KVirtArea`, expected `Mapped`",
                    query_result
                );
            }
        }
    }
}

impl KVirtArea<Untracked> {
    /// Maps untracked pages into the kernel virtual area.
    ///
    /// `pa_range.start` and `pa_range.end` should be aligned to PAGE_SIZE.
    ///
    /// # Safety
    ///
    /// The caller should ensure that
    ///  - the range being mapped does not affect kernel's memory safety;
    ///  - the physical address to be mapped is valid and safe to use;
    ///  - it is allowed to map untracked pages in this virtual address range.
    pub unsafe fn map_untracked_pages(
        &mut self,
        va_range: Range<Vaddr>,
        pa_range: Range<Paddr>,
        prop: PageProperty,
    ) {
        assert!(pa_range.start % PAGE_SIZE == 0);
        assert!(pa_range.end % PAGE_SIZE == 0);
        assert!(va_range.len() == pa_range.len());
        assert!(self.start() <= va_range.start && self.end() >= va_range.end);

        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = page_table.cursor_mut(&va_range).unwrap();
        // SAFETY: The caller of `map_untracked_pages` has ensured the safety of this mapping.
        unsafe {
            cursor.map_pa(&pa_range, prop);
        }
    }

    /// Gets the mapped untracked page.
    ///
    /// This function returns None if the address is not mapped (`NotMapped`),
    /// while panics if the address is mapped to a `Mapped` or `PageTableNode` page.
    pub fn get_untracked_page(&self, addr: Vaddr) -> Option<(Paddr, usize)> {
        let query_result = self.query_page(addr);
        match query_result {
            PageTableItem::MappedUntracked {
                va: _,
                pa,
                len,
                prop: _,
            } => Some((pa, len)),
            PageTableItem::NotMapped { .. } => None,
            _ => {
                panic!(
                    "Found '{:?}' mapped into untracked `KVirtArea`, expected `MappedUntracked`",
                    query_result
                );
            }
        }
    }
}

impl<M: AllocatorSelector + 'static> Drop for KVirtArea<M> {
    fn drop(&mut self) {
        // 1. unmap all mapped pages.
        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let range = self.start()..self.end();
        let mut cursor = page_table.cursor_mut(&range).unwrap();

        loop {
            let result = unsafe { cursor.take_next(self.end() - cursor.virt_addr()) };
            match result {
                PageTableItem::NotMapped { .. } => {
                    break;
                }
                _ => {
                    // Not flushing TLB for mapped pages are fine as it's never reused.
                    // FIXME: think of a way to flush if we want to reuse.
                }
            }
        }

        // 2. free the virtual block
        let allocator = M::select_allocator();
        allocator.free(range);
    }
}
