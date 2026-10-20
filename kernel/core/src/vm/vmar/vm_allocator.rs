// SPDX-License-Identifier: MPL-2.0

//! Utility functions to allocate and lock an unmapped range.

use core::ops::Range;

use align_ext::AlignExt;
use osdk_heap_allocator::{CpuLocalBox, alloc_cpu_local};
use ostd::{
    cpu::{CpuId, PinCurrentCpu, all_cpus, num_cpus},
    mm::{HIGHEST_PAGING_LEVEL, PAGE_SIZE, Vaddr, num_subpages_per_huge, page_size_at},
    sync::SpinLock,
    task::DisabledPreemptGuard,
    util::id_set::Id,
};

use crate::{
    error::{Errno, Error},
    prelude::Result,
    vm::vmar::{
        VMAR_CAP_ADDR, VMAR_LOWEST_ADDR, VmarSpace,
        cursor::CursorExt,
        interval_set::Interval,
        util::{get_intersected_range, is_intersected},
        vmar_impls::{PteRangeMeta, VmarCursorMut},
    },
};

/// A virtual address range allocator.
pub(super) struct VirtualAddressAllocator {
    /// Per-CPU hints, which may overlap mappings or pending selections.
    /// Every cached allocation must revalidate authoritative Aux metadata under PT.
    /// Lock order: PT -> one cache. Never acquire PT while holding a cache lock.
    must_be_free: CpuLocalBox<SpinLock<Range<Vaddr>>>,
    #[cfg(ktest)]
    test_pause: tests::Pause,
}

impl VirtualAddressAllocator {
    /// Creates a new allocator that covers the entire VM range.
    pub(super) fn new() -> Result<Self> {
        let must_be_free = alloc_cpu_local(|cpu| SpinLock::new(assigned_range_on_cpu(cpu)))?;
        Ok(Self {
            must_be_free,
            #[cfg(ktest)]
            test_pause: tests::Pause::new(),
        })
    }

    /// Forks from another allocator and returns the copy.
    ///
    /// This must be called when the entire page table is locked.
    pub(super) fn fork_from(&self) -> Result<Self> {
        let must_be_free =
            alloc_cpu_local(|cpu| SpinLock::new(self.must_be_free.get_on_cpu(cpu).lock().clone()))?;
        Ok(Self {
            must_be_free,
            #[cfg(ktest)]
            test_pause: tests::Pause::new(),
        })
    }

    /// Truncates cache hints and returns a cursor covering the range.
    pub(super) fn alloc_specific_and_lock<'a>(
        &self,
        guard: &'a DisabledPreemptGuard,
        vmar_space: &'a VmarSpace,
        range: &Range<Vaddr>,
    ) -> VmarCursorMut<'a> {
        self.alloc_specific_and_lock_larger(guard, vmar_space, range, range)
    }

    /// Truncates cache hints and returns a cursor covering a larger range.
    pub(super) fn alloc_specific_and_lock_larger<'a>(
        &self,
        guard: &'a DisabledPreemptGuard,
        vmar_space: &'a VmarSpace,
        range: &Range<Vaddr>,
        lock_range: &Range<Vaddr>,
    ) -> VmarCursorMut<'a> {
        #[cfg(ktest)]
        self.test_pause.before_pt(tests::FIXED);
        let cursor = vmar_space.cursor_mut(guard, lock_range).unwrap();
        // Cache entries are hints; no simultaneous snapshot is required.
        for cpu in cpu_range_for_vaddr_range(range) {
            let mut hint = self.must_be_free.get_on_cpu(cpu.try_into().unwrap()).lock();
            *hint = truncate_get_largest(&hint, range);
        }
        cursor
    }

    /// Allocates a virtual address range and gets a cursor covering it.
    pub(super) fn alloc_and_lock<'a>(
        &self,
        guard: &'a DisabledPreemptGuard,
        vmspace: &'a VmarSpace,
        size: usize,
        align: usize,
    ) -> Result<(Vaddr, VmarCursorMut<'a>)> {
        let cur_cpu = if cfg!(feature = "single_vmar_alloc") {
            CpuId::bsp()
        } else {
            guard.current_cpu()
        };

        // Fast path by querying the `must_be_free` range.
        if let Ok(va) = self.alloc_from_cpu_must_free(cur_cpu, size, align) {
            #[cfg(ktest)]
            self.test_pause.before_pt(tests::CACHED);
            let mut cursor = vmspace.cursor_mut(guard, &(va..va + size))?;
            if cursor.find_next_mapped_with(va + size, |_| ()).is_none() {
                return Ok((va, cursor));
            }
            // The per-CPU range is only a cache. Keep its conservative
            // truncation and retry using authoritative page-table metadata.
            drop(cursor);
        }

        // Try other CPUs' fast path.
        for cpu_id in all_cpus() {
            if cpu_id == cur_cpu {
                continue;
            }
            if let Ok(va) = self.alloc_from_cpu_must_free(cpu_id, size, align) {
                #[cfg(ktest)]
                self.test_pause.before_pt(tests::CACHED);
                let mut cursor = vmspace.cursor_mut(guard, &(va..va + size))?;
                if cursor.find_next_mapped_with(va + size, |_| ()).is_none() {
                    return Ok((va, cursor));
                }
                drop(cursor);
            }
        }

        // Try this CPUs' full assigned range.
        if let Ok(res) = self.try_lock_and_alloc_from(
            guard,
            vmspace,
            &assigned_range_on_cpu(cur_cpu),
            size,
            align,
        ) {
            return Ok(res);
        }

        // Try all the assigned ranges of each CPU.
        for cpu_id in all_cpus() {
            if cpu_id == cur_cpu {
                continue;
            }
            if let Ok(res) = self.try_lock_and_alloc_from(
                guard,
                vmspace,
                &assigned_range_on_cpu(cpu_id),
                size,
                align,
            ) {
                return Ok(res);
            }
        }

        // Try the full userspace range.
        let full_range = VMAR_LOWEST_ADDR..VMAR_CAP_ADDR;
        self.try_lock_and_alloc_from(guard, vmspace, &full_range, size, align)
    }

    /// Allocates and locks a virtual address range within the given range.
    #[cfg(target_arch = "x86_64")]
    pub(super) fn alloc_and_lock_in_range<'a>(
        &self,
        guard: &'a DisabledPreemptGuard,
        vmspace: &'a VmarSpace,
        range: &Range<Vaddr>,
        size: usize,
        align: usize,
    ) -> Result<(Vaddr, VmarCursorMut<'a>)> {
        self.try_lock_and_alloc_from(guard, vmspace, range, size, align)
    }

    /// Allocates a virtual address range and gets a cursor covering the given range.
    ///
    /// This function is similar to [`Self::alloc_and_lock`], but it also ensures that
    /// the returned cursor covers the given range.
    pub(super) fn alloc_and_lock_covering_another<'a>(
        &self,
        guard: &'a DisabledPreemptGuard,
        vmspace: &'a VmarSpace,
        range: Range<Vaddr>,
        size: usize,
        align: usize,
    ) -> Result<(Vaddr, VmarCursorMut<'a>)> {
        let cpu_range = cpu_range_for_vaddr_range(&range);

        // Fast path.
        if cpu_range.len() == 1
            && let Ok(va) = self.alloc_from_cpu_must_free(
                CpuId::try_from(cpu_range.start).unwrap(),
                size,
                align,
            )
        {
            let lock_range = range.start.min(va)..range.end.max(va + size);
            #[cfg(ktest)]
            self.test_pause.before_pt(tests::REMAP_CACHED);
            let mut cursor = vmspace.cursor_mut(guard, &lock_range)?;
            cursor.jump(va).unwrap();
            if cursor.find_next_mapped_with(va + size, |_| ()).is_none() {
                cursor.jump(lock_range.start).unwrap();
                return Ok((va, cursor));
            }
            drop(cursor);
        }

        // Slow path: allocate from the assigned ranges.
        let start_va = assigned_range_on_cpu(cpu_range.start.try_into().unwrap()).start;
        let end_va = assigned_range_on_cpu((cpu_range.end - 1).try_into().unwrap()).end;
        let range = start_va..end_va;

        if !range.is_empty()
            && let Ok(res) = self.try_lock_and_alloc_from(guard, vmspace, &range, size, align)
        {
            return Ok(res);
        }

        // Try the full userspace range.
        let full_range = VMAR_LOWEST_ADDR..VMAR_CAP_ADDR;
        self.try_lock_and_alloc_from(guard, vmspace, &full_range, size, align)
    }

    fn alloc_from_cpu_must_free(&self, cpu: CpuId, size: usize, align: usize) -> Result<Vaddr> {
        let mut must_be_free = self.must_be_free.get_on_cpu(cpu).lock();

        alloc_from_free_range(must_be_free.clone(), size, align).map(|va| {
            *must_be_free = truncate_get_largest(&must_be_free, &(va..va + size));
            va
        })
    }

    fn try_lock_and_alloc_from<'a>(
        &self,
        guard: &'a DisabledPreemptGuard,
        vmspace: &'a VmarSpace,
        range: &Range<Vaddr>,
        size: usize,
        align: usize,
    ) -> Result<(Vaddr, VmarCursorMut<'a>)> {
        if !can_alloc_from_free_range(range, size, align) {
            return Err(Error::with_message(
                Errno::ENOMEM,
                "the given range cannot fit the allocation",
            ));
        }

        // Search under PT, then briefly refill individual hints. A pending cached
        // selection may be reintroduced here; its later Aux check resolves races.
        #[cfg(ktest)]
        self.test_pause.before_pt(tests::SLOW);
        let mut cursor = vmspace.cursor_mut(guard, range)?;
        let (va, range) = find_fit_range_in_cursor(&mut cursor, size, align)?;

        let remain = truncate_get_largest(&range, &(va..va + size));
        if !remain.is_empty() {
            for cpu in cpu_range_for_vaddr_range(&remain) {
                let cpu_id = CpuId::try_from(cpu).unwrap();
                let free_remain = get_intersected_range(&remain, &assigned_range_on_cpu(cpu_id));
                let mut hint = self.must_be_free.get_on_cpu(cpu_id).lock();
                if free_remain.len() > hint.len() {
                    *hint = free_remain;
                }
            }
        }

        Ok((va, cursor))
    }
}

/// Tries to allocate a virtual address range in the cursor's guard range.
///
/// It also returns the free range found in the process. The allocated address
/// is within the free range.
fn find_fit_range_in_cursor(
    cursor: &mut VmarCursorMut,
    size: usize,
    align: usize,
) -> Result<(Vaddr, Range<Vaddr>)> {
    let guard_range = cursor.guard_va_range();
    cursor.jump(guard_range.start).unwrap();

    // Search top-down for a suitable range.
    let mut search_end = guard_range.end;
    cursor.jump(search_end - PAGE_SIZE).unwrap();
    while let Some(candidate) = search_end.checked_sub(size) {
        if candidate.align_down(align) < guard_range.start {
            break;
        }

        let cur_level = cursor.level();
        let cur_va = cursor.virt_addr();

        let Some(meta) = cursor.aux_meta().inner.find_prev(&(cur_va + 1)) else {
            let cur_free_start = cursor.virt_addr().align_down(page_size_at(cur_level + 1));
            if let Ok(va) = alloc_from_free_range(cur_free_start..search_end, size, align) {
                return Ok((va, cur_free_start..search_end));
            }

            // Pop level and continue searching.
            if cursor.level() == cursor.guard_level() {
                break;
            } else {
                cursor.pop_level();
                let prev_addr = cursor.cur_va_range().start - PAGE_SIZE;
                if cursor.jump(prev_addr).is_err() {
                    break;
                }
                continue;
            }
        };
        let possible_end = meta.range().end.max(guard_range.start);
        if possible_end < search_end
            && let Ok(va) = alloc_from_free_range(possible_end..search_end, size, align)
        {
            return Ok((va, possible_end..search_end));
        }
        match meta {
            PteRangeMeta::ChildPt(r) => {
                debug_assert!(r.start < cursor.virt_addr());
                if r.end < guard_range.start {
                    break;
                }
                if r.end - PAGE_SIZE < cursor.virt_addr() {
                    cursor.jump(r.end - PAGE_SIZE).unwrap();
                }
                cursor.push_level_if_exists().unwrap();
            }
            PteRangeMeta::VmMapping(vm_mapping) => {
                if vm_mapping.range().start <= guard_range.start {
                    break;
                }
                search_end = vm_mapping.range().start;
                if cursor.jump(search_end - PAGE_SIZE).is_err() {
                    break;
                }
            }
        }
    }

    Err(Error::with_message(
        Errno::ENOMEM,
        "no suitable range found",
    ))
}

/// Returns the assigned virtual address range for the given CPU.
///
/// The assigned range is firstly searched for free space to allocate.
fn assigned_range_on_cpu(cpu: CpuId) -> Range<Vaddr> {
    if cfg!(feature = "single_vmar_alloc") {
        return if cpu == CpuId::bsp() {
            VMAR_LOWEST_ADDR..VMAR_CAP_ADDR
        } else {
            VMAR_LOWEST_ADDR..VMAR_LOWEST_ADDR
        };
    }
    let num_cpus = num_cpus();
    let per_cpu_range_size = assigned_range_size_for(num_cpus);

    let start = per_cpu_range_size * (cpu.as_usize());
    let end = if cpu.as_usize() == num_cpus - 1 {
        // Add the residue to the last CPU's range.
        VMAR_CAP_ADDR
    } else {
        start + per_cpu_range_size
    };

    start.max(VMAR_LOWEST_ADDR)..end.max(VMAR_LOWEST_ADDR)
}

/// Returns the range of CPU IDs that the given virtual address belongs to.
fn cpu_range_for_vaddr_range(range: &Range<Vaddr>) -> Range<usize> {
    debug_assert!(range.start < range.end);
    if cfg!(feature = "single_vmar_alloc") {
        return 0..1;
    }

    let num_cpus = num_cpus();
    let per_cpu_range_size = assigned_range_size_for(num_cpus);

    let start_cpu = (range.start / per_cpu_range_size).min(num_cpus - 1);
    let end_cpu = ((range.end - 1) / per_cpu_range_size).min(num_cpus - 1);

    start_cpu..end_cpu + 1
}

/// Returns the assigned range size for CPUs (except for the last CPU).
///
/// Try out best to make the size aligned so the lock protocol performs well.
const fn assigned_range_size_for(num_cpus: usize) -> usize {
    let align_to_paging_level = if num_cpus < num_subpages_per_huge() / 2 {
        HIGHEST_PAGING_LEVEL
    } else if num_cpus < num_subpages_per_huge().pow(2) / 2 {
        HIGHEST_PAGING_LEVEL - 1
    } else if num_cpus < num_subpages_per_huge().pow(3) / 2 {
        HIGHEST_PAGING_LEVEL - 2
    } else {
        HIGHEST_PAGING_LEVEL - 3
    };

    let align_to = page_size_at(align_to_paging_level);

    (VMAR_CAP_ADDR / num_cpus) & !(align_to - 1)
}

/// Allocates a virtual address range from the given free range.
fn alloc_from_free_range(range: Range<Vaddr>, size: usize, align: usize) -> Result<Vaddr> {
    if range.len() >= size {
        let aligned_start = (range.end - size).align_down(align);
        if aligned_start >= range.start {
            return Ok(aligned_start);
        }
    }

    Err(Error::with_message(
        Errno::ENOMEM,
        "no suitable range found in the free range",
    ))
}

fn can_alloc_from_free_range(range: &Range<Vaddr>, size: usize, align: usize) -> bool {
    alloc_from_free_range(range.clone(), size, align).is_ok()
}

/// Calculates `range` - `cut` and return the largest remaining piece.
fn truncate_get_largest(range: &Range<Vaddr>, cut: &Range<Vaddr>) -> Range<Vaddr> {
    if !is_intersected(range, cut) {
        return range.clone();
    }

    let left = range.start..cut.start.max(range.start);
    let right = cut.end.min(range.end)..range.end;

    if left.len() > right.len() {
        left
    } else {
        right
    }
}

#[cfg(ktest)]
mod tests;
