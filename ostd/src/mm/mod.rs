// SPDX-License-Identifier: MPL-2.0

//! Virtual memory (VM).

/// Virtual addresses.
pub type Vaddr = usize;

/// Physical addresses.
pub type Paddr = usize;

pub(crate) mod dma;
pub mod frame;
pub(crate) mod heap_allocator;
mod io;
pub(crate) mod kspace;
mod offset;
pub(crate) mod page;
pub(crate) mod page_prop;
pub(crate) mod page_table;
pub mod stat;
pub mod tlb;
pub mod vm_space;

use core::{fmt::Debug, ops::Range};

pub use self::{
    dma::{Daddr, DmaCoherent, DmaDirection, DmaStream, DmaStreamSlice, HasDaddr},
    frame::{options::FrameAllocOptions, Frame, Segment},
    io::{
        Fallible, FallibleVmRead, FallibleVmWrite, Infallible, PodOnce, VmIo, VmIoOnce, VmReader,
        VmWriter,
    },
    page_prop::{CachePolicy, PageFlags, PageProperty},
    vm_space::VmSpace,
};
pub(crate) use self::{
    kspace::paddr_to_vaddr, page::meta::init as init_page_meta, page_prop::PrivilegedPageFlags,
    page_table::PageTable,
};
use crate::arch::mm::PagingConsts;

/// The level of a page table node or a frame.
pub type PagingLevel = u8;

/// A minimal set of constants that determines the paging system.
/// This provides an abstraction over most paging modes in common architectures.
pub(crate) trait PagingConstsTrait: Clone + Debug + Default + Sync + 'static {
    /// The smallest page size.
    /// This is also the page size at level 1 page tables.
    const BASE_PAGE_SIZE: usize;

    /// The number of levels in the page table.
    /// The numbering of levels goes from deepest node to the root node. For example,
    /// the level 1 to 5 on AMD64 corresponds to Page Tables, Page Directory Tables,
    /// Page Directory Pointer Tables, Page-Map Level-4 Table, and Page-Map Level-5
    /// Table, respectively.
    const NR_LEVELS: PagingLevel;

    /// The highest level that a PTE can be directly used to translate a VA.
    /// This affects the the largest page size supported by the page table.
    const HIGHEST_TRANSLATION_LEVEL: PagingLevel;

    /// The size of a PTE.
    const PTE_SIZE: usize;

    /// The address width may be BASE_PAGE_SIZE.ilog2() + NR_LEVELS * IN_FRAME_INDEX_BITS.
    /// If it is shorter than that, the higher bits in the highest level are ignored.
    const ADDRESS_WIDTH: usize;
}

/// The page size
pub const PAGE_SIZE: usize = page_size::<PagingConsts>(1);

/// The page size at a given level.
pub(crate) const fn page_size<C: PagingConstsTrait>(level: PagingLevel) -> usize {
    C::BASE_PAGE_SIZE << (nr_subpage_per_huge::<C>().ilog2() as usize * (level as usize - 1))
}

/// The number of sub pages in a huge page.
pub(crate) const fn nr_subpage_per_huge<C: PagingConstsTrait>() -> usize {
    C::BASE_PAGE_SIZE / C::PTE_SIZE
}

/// The number of base pages in a huge page at a given level.
#[allow(dead_code)]
pub(crate) const fn nr_base_per_page<C: PagingConstsTrait>(level: PagingLevel) -> usize {
    page_size::<C>(level) / C::BASE_PAGE_SIZE
}

/// The maximum virtual address of user space (non inclusive).
///
/// Typical 64-bit systems have at least 48-bit virtual address space.
/// A typical way to reserve half of the address space for the kernel is
/// to use the highest 48-bit virtual address space.
///
/// Also, the top page is not regarded as usable since it's a workaround
/// for some x86_64 CPUs' bugs. See
/// <https://github.com/torvalds/linux/blob/480e035fc4c714fb5536e64ab9db04fedc89e910/arch/x86/include/asm/page_64.h#L68-L78>
/// for the rationale.
pub const MAX_USERSPACE_VADDR: Vaddr = 0x0000_8000_0000_0000 - PAGE_SIZE;

/// The kernel address space.
/// There are the high canonical addresses defined in most 48-bit width
/// architectures.
pub(crate) const KERNEL_VADDR_RANGE: Range<Vaddr> = 0xffff_8000_0000_0000..0xffff_ffff_ffff_0000;

/// Gets physical address trait
pub trait HasPaddr {
    /// Returns the physical address.
    fn paddr(&self) -> Paddr;
}

/// Checks if the given address is page-aligned.
pub const fn is_page_aligned(p: usize) -> bool {
    (p & (PAGE_SIZE - 1)) == 0
}

pub use mem_profile::*;
mod mem_profile {
    use alloc::{alloc::Layout, collections::BTreeMap};

    use crate::sync::SpinLock;

    #[derive(Debug)]
    pub struct AllocRecord {
        pub layout: Layout,
        pub stack: [usize; 20],
    }

    impl AllocRecord {
        #[inline(always)]
        pub fn new(layout: Layout) -> Self {
            use core::ffi::c_void;

            use unwinding::abi::{
                UnwindContext, UnwindReasonCode, _Unwind_Backtrace, _Unwind_GetIP,
            };

            struct StackData {
                stack: [usize; 20],
                stack_top: usize,
            }

            extern "C" fn callback(
                unwind_ctx: &UnwindContext<'_>,
                arg: *mut c_void,
            ) -> UnwindReasonCode {
                let data = unsafe { &mut *(arg as *mut StackData) };
                let pc = _Unwind_GetIP(unwind_ctx);
                if data.stack_top < data.stack.len() {
                    data.stack[data.stack_top] = pc;
                    data.stack_top += 1;
                }
                UnwindReasonCode::NO_REASON
            }

            let mut data = StackData {
                stack: [0; 20],
                stack_top: 0,
            };
            _Unwind_Backtrace(callback, &mut data as *mut _ as _);
            let StackData {
                stack,
                stack_top: _,
            } = data;

            Self { layout, stack }
        }
    }

    static PROFILE_DATA: SpinLock<Option<BTreeMap<usize, AllocRecord>>> = SpinLock::new(None);

    /// Start memory profiling.
    pub fn start_mem_profile() {
        crate::early_println!("[ostd] start mem profile");
        let old = PROFILE_DATA.lock().replace(BTreeMap::new());
        assert!(old.is_none());
    }

    /// Stop memory profiling and return the result.
    pub fn stop_mem_profile() -> BTreeMap<usize, AllocRecord> {
        crate::early_println!("[kern] stop mem profile");
        let result = PROFILE_DATA.lock().take().unwrap();
        result
    }

    #[inline(always)]
    pub(super) fn debug_profile(ptr: usize, layout: Layout) {
        if let Some(mut guard) = PROFILE_DATA.try_lock() {
            if let Some(profile_data) = guard.as_mut() {
                let record = AllocRecord::new(layout);
                profile_data.insert(ptr, record);
            }
        }
    }

    #[inline(always)]
    pub(super) fn debug_remove_profile(ptr: usize) {
        if let Some(mut guard) = PROFILE_DATA.try_lock() {
            if let Some(profile_data) = guard.as_mut() {
                let _ = profile_data.remove(&ptr);
            }
        }
    }
}
