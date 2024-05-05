// SPDX-License-Identifier: MPL-2.0

use alloc::fmt;

use pod::Pod;
use x86_64::{instructions::tlb, structures::paging::PhysFrame, VirtAddr};

use crate::vm::{
    page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags as PrivFlags},
    page_table::PageTableEntryTrait,
    Paddr, PagingConstsTrait, Vaddr,
};

pub(crate) const NR_ENTRIES_PER_PAGE: usize = 512;

#[derive(Debug)]
pub struct PagingConsts {}

impl PagingConstsTrait for PagingConsts {
    const BASE_PAGE_SIZE: usize = 4096;
    const NR_LEVELS: usize = 4;
    const HIGHEST_TRANSLATION_LEVEL: usize = 2;
    const PTE_SIZE: usize = core::mem::size_of::<PageTableEntry>();
}

bitflags::bitflags! {
    #[derive(Pod)]
    #[repr(C)]
    /// Possible flags for a page table entry.
    pub struct PageTableFlags: usize {
        /// Specifies whether the mapped frame or page table is loaded in memory.
        const PRESENT =         1 << 0;
        /// Controls whether writes to the mapped frames are allowed.
        const WRITABLE =        1 << 1;
        /// Controls whether accesses from userspace (i.e. ring 3) are permitted.
        const USER =            1 << 2;
        /// If this bit is set, a “write-through” policy is used for the cache, else a “write-back”
        /// policy is used.
        const WRITE_THROUGH =   1 << 3;
        /// Disables caching for the pointed entry is cacheable.
        const NO_CACHE =        1 << 4;
        /// Whether this entry has been used for linear-address translation.
        const ACCESSED =        1 << 5;
        /// Whether the memory area represented by this entry is modified.
        const DIRTY =           1 << 6;
        /// Only in the non-starting and non-ending levels, indication of huge page.
        const HUGE =            1 << 7;
        /// Indicates that the mapping is present in all address spaces, so it isn't flushed from
        /// the TLB on an address space switch.
        const GLOBAL =          1 << 8;
        /// TDX shared bit.
        #[cfg(feature = "intel_tdx")]
        const SHARED =          1 << 51;
        /// Forbid execute codes on the page. The NXE bits in EFER msr must be set.
        const NO_EXECUTE =      1 << 63;
    }
}

pub fn tlb_flush(vaddr: Vaddr) {
    tlb::flush(VirtAddr::new(vaddr as u64));
}

#[derive(Clone, Copy, Pod)]
#[repr(C)]
pub struct PageTableEntry(usize);

/// Activate the given level 4 page table.
/// The cache policy of the root page table frame is controlled by `root_pt_cache`.
///
/// ## Safety
///
/// Changing the level 4 page table is unsafe, because it's possible to violate memory safety by
/// changing the page mapping.
pub unsafe fn activate_page_table(root_paddr: Paddr, root_pt_cache: CachePolicy) {
    x86_64::registers::control::Cr3::write(
        PhysFrame::from_start_address(x86_64::PhysAddr::new(root_paddr as u64)).unwrap(),
        match root_pt_cache {
            CachePolicy::Writeback => x86_64::registers::control::Cr3Flags::empty(),
            CachePolicy::Writethrough => {
                x86_64::registers::control::Cr3Flags::PAGE_LEVEL_WRITETHROUGH
            }
            CachePolicy::Uncacheable => {
                x86_64::registers::control::Cr3Flags::PAGE_LEVEL_CACHE_DISABLE
            }
            _ => panic!("unsupported cache policy for the root page table"),
        },
    );
}

pub fn current_page_table_paddr() -> Paddr {
    x86_64::registers::control::Cr3::read()
        .0
        .start_address()
        .as_u64() as Paddr
}

impl PageTableEntry {
    /// 51:12
    #[cfg(not(feature = "intel_tdx"))]
    const PHYS_ADDR_MASK: usize = 0xF_FFFF_FFFF_F000;
    #[cfg(feature = "intel_tdx")]
    const PHYS_ADDR_MASK: usize = 0x7_FFFF_FFFF_F000;
}

/// Parse a bit-flag bits `val` in the representation of `from` to `to` in bits.
macro_rules! parse_flags {
    ($val:expr, $from:expr, $to:expr) => {
        ($val as usize & $from.bits() as usize) >> $from.bits().ilog2() << $to.bits().ilog2()
    };
}

impl PageTableEntryTrait for PageTableEntry {
    fn new_absent() -> Self {
        Self(0)
    }

    fn is_present(&self) -> bool {
        self.0 & PageTableFlags::PRESENT.bits() != 0
    }

    fn new(paddr: Paddr, prop: PageProperty, huge: bool, last: bool) -> Self {
        let mut flags =
            PageTableFlags::PRESENT.bits() | (huge as usize) << PageTableFlags::HUGE.bits().ilog2();
        if !huge && !last {
            // In x86 if it's an intermediate PTE, it's better to have the same permissions
            // as the most permissive child (to reduce hardware page walk accesses). But we
            // don't have a mechanism to keep it generic across architectures, thus just
            // setting it to be the most permissive.
            flags |= PageTableFlags::WRITABLE.bits() | PageTableFlags::USER.bits();
            #[cfg(feature = "intel_tdx")]
            {
                flags |= parse_flags!(
                    prop.priv_flags.bits(),
                    PrivFlags::SHARED,
                    PageTableFlags::SHARED
                );
            }
        } else {
            flags |= parse_flags!(prop.flags.bits(), PageFlags::W, PageTableFlags::WRITABLE)
                | parse_flags!(!prop.flags.bits(), PageFlags::X, PageTableFlags::NO_EXECUTE)
                | parse_flags!(
                    prop.flags.bits(),
                    PageFlags::ACCESSED,
                    PageTableFlags::ACCESSED
                )
                | parse_flags!(prop.flags.bits(), PageFlags::DIRTY, PageTableFlags::DIRTY)
                | parse_flags!(
                    prop.priv_flags.bits(),
                    PrivFlags::USER,
                    PageTableFlags::USER
                )
                | parse_flags!(
                    prop.priv_flags.bits(),
                    PrivFlags::GLOBAL,
                    PageTableFlags::GLOBAL
                );
            #[cfg(feature = "intel_tdx")]
            {
                flags |= parse_flags!(
                    prop.priv_flags.bits(),
                    PrivFlags::SHARED,
                    PageTableFlags::SHARED
                );
            }
        }
        match prop.cache {
            CachePolicy::Writeback => {}
            CachePolicy::Writethrough => {
                flags |= PageTableFlags::WRITE_THROUGH.bits();
            }
            CachePolicy::Uncacheable => {
                flags |= PageTableFlags::NO_CACHE.bits();
            }
            _ => panic!("unsupported cache policy"),
        }
        Self(paddr & Self::PHYS_ADDR_MASK | flags)
    }

    fn paddr(&self) -> Paddr {
        self.0 & Self::PHYS_ADDR_MASK
    }

    fn prop(&self) -> PageProperty {
        let flags = parse_flags!(self.0, PageTableFlags::PRESENT, PageFlags::R)
            | parse_flags!(self.0, PageTableFlags::WRITABLE, PageFlags::W)
            | parse_flags!(!self.0, PageTableFlags::NO_EXECUTE, PageFlags::X)
            | parse_flags!(self.0, PageTableFlags::ACCESSED, PageFlags::ACCESSED)
            | parse_flags!(self.0, PageTableFlags::DIRTY, PageFlags::DIRTY);
        let priv_flags = parse_flags!(self.0, PageTableFlags::USER, PrivFlags::USER)
            | parse_flags!(self.0, PageTableFlags::GLOBAL, PrivFlags::GLOBAL);
        #[cfg(feature = "intel_tdx")]
        let priv_flags =
            priv_flags | parse_flags!(self.0, PageTableFlags::SHARED, PrivFlags::SHARED);
        let cache = if self.0 & PageTableFlags::NO_CACHE.bits() != 0 {
            CachePolicy::Uncacheable
        } else if self.0 & PageTableFlags::WRITE_THROUGH.bits() != 0 {
            CachePolicy::Writethrough
        } else {
            CachePolicy::Writeback
        };
        PageProperty {
            flags: PageFlags::from_bits(flags as u8).unwrap(),
            cache,
            priv_flags: PrivFlags::from_bits(priv_flags as u8).unwrap(),
        }
    }

    fn is_huge(&self) -> bool {
        self.0 & PageTableFlags::HUGE.bits() != 0
    }
}

impl fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut f = f.debug_struct("PageTableEntry");
        f.field("raw", &format_args!("{:#x}", self.0))
            .field("paddr", &format_args!("{:#x}", self.paddr()))
            .field("present", &self.is_present())
            .field(
                "flags",
                &PageTableFlags::from_bits_truncate(self.0 & !Self::PHYS_ADDR_MASK),
            )
            .field("prop", &self.prop())
            .finish()
    }
}
