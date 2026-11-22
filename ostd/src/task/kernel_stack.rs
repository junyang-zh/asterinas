// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use crate::{
    arch::mm::tlb_flush_addr_range,
    cpu::{AtomicCpuSet, CpuSet, PinCurrentCpu},
    impl_frame_meta_for,
    irq::DisabledLocalIrqGuard,
    mm::{
        FrameAllocOptions, PAGE_SIZE,
        kspace::kvirt_area::KVirtArea,
        page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
    },
    prelude::*,
    sync::{LocalIrqDisabled, SpinLock},
};

/// The kernel stack size of a task, specified in pages.
///
/// By default, we choose a rather large stack size.
/// OSTD users can choose a smaller size by specifying
/// the `OSTD_TASK_STACK_SIZE_IN_PAGES` environment variable
/// at build time.
const STACK_SIZE_IN_PAGES: u32 =
    if let Some(size_str) = option_env!("OSTD_TASK_STACK_SIZE_IN_PAGES") {
        match u32::from_str_radix(size_str, 10) {
            Ok(size) => size,
            Err(_) => panic!(
                "The environment variable `OSTD_TASK_STACK_SIZE_IN_PAGES` \
                    specifies an invalid value"
            ),
        }
    } else {
        DEFAULT_STACK_SIZE_IN_PAGES
    };

/// The default kernel stack size of a task, specified in pages.
const DEFAULT_STACK_SIZE_IN_PAGES: u32 = 128;

const KERNEL_STACK_SIZE: usize = STACK_SIZE_IN_PAGES as usize * PAGE_SIZE;

// Each online CPU contributes space for one idle stack, up to 16 MiB of
// physical pages. Creation and retirement can run on different CPUs.
const MAX_CACHED_STACKS: usize = match (16 * 1024 * 1024usize).checked_div(KERNEL_STACK_SIZE) {
    Some(count) if count < 512 => count,
    Some(_) => 512,
    None => 0,
};

struct StackCache {
    areas: [Option<KVirtArea>; MAX_CACHED_STACKS],
    len: usize,
}

impl StackCache {
    fn pop(&mut self) -> Option<KVirtArea> {
        self.len = self.len.checked_sub(1)?;
        self.areas[self.len].take()
    }
}

static STACK_CACHE: SpinLock<StackCache, LocalIrqDisabled> = SpinLock::new(StackCache {
    areas: [const { None }; MAX_CACHED_STACKS],
    len: 0,
});

#[derive(Debug)]
pub(super) struct KernelStack {
    kvirt_area: Option<KVirtArea>,
    tlb_coherent: AtomicCpuSet,
    end_vaddr: Vaddr,
}

#[derive(Debug, Default)]
struct KernelStackMeta;

impl_frame_meta_for!(KernelStackMeta);

impl KernelStack {
    /// Generates a kernel stack with guard pages.
    ///
    /// 4 additional pages are allocated and regarded as guard pages, which
    /// should not be accessed.
    pub(super) fn new_with_guard_page() -> Result<Self> {
        let cached = STACK_CACHE.lock().pop();
        let area = match cached {
            Some(area) => area,
            None => Self::map_guarded_area()?,
        };
        let end_vaddr = area.start() + 2 * PAGE_SIZE + KERNEL_STACK_SIZE;
        Ok(Self {
            kvirt_area: Some(area),
            tlb_coherent: AtomicCpuSet::new(CpuSet::new_empty()),
            end_vaddr,
        })
    }

    fn map_guarded_area() -> Result<KVirtArea> {
        let pages = FrameAllocOptions::new()
            .zeroed(false)
            .alloc_segment_with(KERNEL_STACK_SIZE / PAGE_SIZE, |_| KernelStackMeta)?;
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::empty(),
        };
        Ok(KVirtArea::map_frames(
            KERNEL_STACK_SIZE + 4 * PAGE_SIZE,
            2 * PAGE_SIZE,
            pages.into_iter(),
            prop,
        ))
    }

    /// Flushes the TLB for the current CPU if necessary.
    pub(super) fn flush_tlb(&self, irq_guard: &DisabledLocalIrqGuard) {
        let cur_cpu = irq_guard.current_cpu();
        if !self.tlb_coherent.contains(cur_cpu, Ordering::Relaxed) {
            tlb_flush_addr_range(&self.kvirt_area.as_ref().unwrap().range());
            self.tlb_coherent.add(cur_cpu, Ordering::Relaxed);
        }
    }

    pub(super) fn end_vaddr(&self) -> Vaddr {
        self.end_vaddr
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        let mut cache = STACK_CACHE.lock();
        let index = cache.len;
        if index < crate::cpu::num_cpus().min(MAX_CACHED_STACKS) {
            cache.areas[index] = self.kvirt_area.take();
            cache.len += 1;
        }
        // A surplus area is unmapped by field drop after releasing the lock.
    }
}

#[cfg(ktest)]
mod test {
    use super::*;

    #[ktest]
    fn stack_cache_bounds_and_repeated_reuse() {
        let limit = crate::cpu::num_cpus().min(MAX_CACHED_STACKS);
        let mut stacks = Vec::new();
        for _ in 0..limit + 3 {
            stacks.push(KernelStack::new_with_guard_page().unwrap());
        }
        drop(stacks);
        assert_eq!(STACK_CACHE.lock().len, limit);
        let mut live = Vec::new();
        for _ in 0..limit + 1 {
            let stack = KernelStack::new_with_guard_page().unwrap();
            assert!(live.iter().all(|other: &KernelStack| other.end_vaddr() != stack.end_vaddr()));
            live.push(stack);
        }
        assert_eq!(STACK_CACHE.lock().len, 0);
    }

    #[ktest]
    fn reused_stacks_preserve_guards_and_reset_cpu_tracking() {
        let mut live = Vec::new();
        for _ in 0..crate::cpu::num_cpus().min(MAX_CACHED_STACKS) + 2 {
            let stack = KernelStack::new_with_guard_page().unwrap();
            assert!(live.iter().all(|other: &KernelStack| other.end_vaddr != stack.end_vaddr));
            live.push(stack);
        }
        let stack = live.pop().unwrap();
        let top = stack.end_vaddr();
        {
            let guard = crate::irq::disable_local();
            stack.flush_tlb(&guard);
            assert!(stack.tlb_coherent.contains(guard.current_cpu(), Ordering::Relaxed));
        }
        drop(stack);
        let replacement = KernelStack::new_with_guard_page().unwrap();
        if MAX_CACHED_STACKS != 0 {
            assert_eq!(replacement.end_vaddr(), top);
        }
        let area = replacement.kvirt_area.as_ref().unwrap();
        let guard = crate::irq::disable_local();
        assert!(!replacement.tlb_coherent.contains(guard.current_cpu(), Ordering::Relaxed));
        for (index, addr) in area.range().step_by(PAGE_SIZE).enumerate() {
            let mapped = (2..2 + STACK_SIZE_IN_PAGES as usize).contains(&index);
            assert_eq!(area.query(&guard, addr).is_some(), mapped);
        }
    }
}
