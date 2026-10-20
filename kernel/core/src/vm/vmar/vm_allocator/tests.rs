// SPDX-License-Identifier: MPL-2.0

//! Tests of the real allocator and VMAR, including controlled pending selections.

use core::{
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use ostd::{prelude::ktest, task::disable_preempt};

use super::*;
use crate::{
    fs::pseudofs::SockFs,
    prelude::*,
    process::ProcessVm,
    thread::kernel_thread::ThreadOptions,
    vm::{
        perms::VmPerms,
        vmar::{OffsetType, PageFaultInfo, RemapOldMappingAction, RssType, Vmar, VmarHandle},
    },
};

pub(super) const FIXED: usize = 1;
pub(super) const CACHED: usize = 2;
pub(super) const SLOW: usize = 3;
pub(super) const REMAP_CACHED: usize = 4;
const SPIN_BUDGET: usize = 100_000_000;

/// One per-allocator, one-shot pause. No production field or code is emitted.
/// Neither participant asserts until the hook and any PT cursor are released.
pub(super) struct Pause {
    cpu: AtomicUsize,
    stage: AtomicUsize,
    reached: AtomicBool,
    released: AtomicBool,
    timed_out: AtomicBool,
}

impl Pause {
    pub(super) const fn new() -> Self {
        Self {
            cpu: AtomicUsize::new(usize::MAX),
            stage: AtomicUsize::new(0),
            reached: AtomicBool::new(false),
            released: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
        }
    }

    fn arm(&self, cpu: CpuId, stage: usize) {
        self.cpu.store(cpu.as_usize(), Ordering::Relaxed);
        self.stage.store(stage, Ordering::Release);
    }

    pub(super) fn before_pt(&self, stage: usize) {
        if self.stage.load(Ordering::Acquire) != stage
            || self.cpu.load(Ordering::Relaxed) != CpuId::current_racy().as_usize()
            || self
                .stage
                .compare_exchange(stage, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        self.reached.store(true, Ordering::Release);
        if !wait_flag(&self.released) {
            self.timed_out.store(true, Ordering::Release);
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
    }
}

fn wait_flag(flag: &AtomicBool) -> bool {
    for _ in 0..SPIN_BUDGET {
        if flag.load(Ordering::Acquire) {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn remote_cpu(current: CpuId) -> CpuId {
    all_cpus()
        .find(|cpu| *cpu != current)
        .expect("run allocator concurrency tests with >=2 CPUs")
}

fn allocation_cpu(cpu: CpuId) -> CpuId {
    if cfg!(feature = "single_vmar_alloc") {
        CpuId::bsp()
    } else {
        cpu
    }
}

fn inversion_probe(stage: usize) {
    crate::thread::init();
    let guard = disable_preempt();
    let remote = remote_cpu(guard.current_cpu());
    let allocator = Arc::new(VirtualAddressAllocator::new().unwrap());
    let space = Arc::new(VmarSpace::new());
    let cache_cpu = if stage == CACHED {
        allocation_cpu(remote)
    } else {
        CpuId::bsp()
    };
    allocator.test_pause.arm(remote, stage);
    let cursor = space.cursor_mut(&guard, &(0..VMAR_CAP_ADDR)).unwrap();
    let worker_allocator = allocator.clone();
    let worker_space = space.clone();
    let completed = Arc::new(AtomicBool::new(false));
    let worker_completed = completed.clone();
    let worker = ThreadOptions::new(move || {
        let guard = disable_preempt();
        let success = match stage {
            FIXED => {
                drop(worker_allocator.alloc_specific_and_lock(
                    &guard,
                    &worker_space,
                    &(0x200_000..0x201_000),
                ));
                true
            }
            CACHED => worker_allocator
                .alloc_and_lock(&guard, &worker_space, PAGE_SIZE, PAGE_SIZE)
                .is_ok(),
            SLOW => worker_allocator
                .try_lock_and_alloc_from(
                    &guard,
                    &worker_space,
                    &(0x200_000..0x204_000),
                    PAGE_SIZE,
                    PAGE_SIZE,
                )
                .is_ok(),
            REMAP_CACHED => worker_allocator
                .alloc_and_lock_covering_another(
                    &guard,
                    &worker_space,
                    0x200_000..0x201_000,
                    PAGE_SIZE,
                    PAGE_SIZE,
                )
                .is_ok(),
            _ => unreachable!(),
        };
        worker_completed.store(success, Ordering::Release);
    })
    .cpu_affinity(remote.into())
    .spawn();

    let reached = wait_flag(&allocator.test_pause.reached);
    // Capture without blocking: the old implementation fails this observation.
    let cache_available = allocator
        .must_be_free
        .get_on_cpu(cache_cpu)
        .try_lock()
        .is_some();
    allocator.test_pause.release();
    drop(cursor);
    drop(guard);
    worker.join();
    assert!(reached, "worker did not reach the acquisition hook");
    assert!(!allocator.test_pause.timed_out.load(Ordering::Acquire));
    assert!(completed.load(Ordering::Acquire));
    assert!(
        cache_available,
        "allocator held a cache while about to acquire PT"
    );
}

#[ktest]
fn fixed_does_not_hold_cache_before_pt() {
    inversion_probe(FIXED);
}
#[ktest]
fn cached_does_not_hold_cache_before_pt() {
    inversion_probe(CACHED);
}
#[ktest]
fn slow_does_not_hold_cache_before_pt() {
    inversion_probe(SLOW);
}
#[ktest]
fn remap_does_not_hold_cache_before_pt() {
    inversion_probe(REMAP_CACHED);
}

fn new_vmar() -> VmarHandle {
    crate::thread::init();
    crate::time::clocks::init_for_ktest();
    crate::util::random::init();
    let vmar = VmarHandle::new(ProcessVm::new(SockFs::new_path())).unwrap();
    vmar.process_vm().map_and_init_heap_for_ktest(&vmar).unwrap();
    vmar
}

fn map(
    vmar: &Vmar,
    address: usize,
    pages: usize,
    kind: OffsetType,
    perms: VmPerms,
) -> Result<Vaddr> {
    vmar.new_map(NonZeroUsize::new(pages * PAGE_SIZE).unwrap(), perms)?
        .offset(address, kind)
        .build()
}

fn write_byte(vmar: &Vmar, address: usize, value: u8) {
    assert_eq!(
        vmar.write_alien(address, &mut VmReader::from(&[value][..]).to_fallible())
            .unwrap(),
        1
    );
}

fn read_byte(vmar: &Vmar, address: usize) -> u8 {
    let mut value = [0u8];
    assert_eq!(
        vmar.read_alien(address, &mut VmWriter::from(&mut value[..]).to_fallible())
            .unwrap(),
        1
    );
    value[0]
}

fn empty_hints(vmar: &Vmar) {
    for cpu in all_cpus() {
        *vmar.allocator.must_be_free.get_on_cpu(cpu).lock() = 0..0;
    }
}

#[ktest]
fn fixed_mapping_completes_while_hint_is_held() {
    let vmar = new_vmar();
    let before = vmar.get_mappings_total_size();
    let rss_before = vmar.get_rss_counter(RssType::Anon);
    let base = 0x300_000;
    map(
        &vmar,
        base,
        1,
        OffsetType::FixedNoReplace,
        VmPerms::READ | VmPerms::WRITE,
    )
    .unwrap();
    write_byte(&vmar, base, 0x93);
    let address = base + 2 * PAGE_SIZE;
    let controller_guard = disable_preempt();
    let remote = remote_cpu(controller_guard.current_cpu());
    let cache_cpu =
        CpuId::try_from(cpu_range_for_vaddr_range(&(address..address + PAGE_SIZE)).start).unwrap();
    *vmar.allocator.must_be_free.get_on_cpu(cache_cpu).lock() = address..address + PAGE_SIZE;
    vmar.allocator.test_pause.arm(remote, FIXED);
    let result = Arc::new(SpinLock::<Option<Result<Vaddr>>>::new(None));
    let completed = Arc::new(AtomicBool::new(false));
    let worker_result = result.clone();
    let worker_completed = completed.clone();
    let worker_vmar = vmar.clone_arc();
    let worker = ThreadOptions::new(move || {
        let outcome = map(
            &worker_vmar,
            address,
            1,
            OffsetType::FixedNoReplace,
            VmPerms::READ,
        );
        *worker_result.lock() = Some(outcome);
        worker_completed.store(true, Ordering::Release);
    })
    .cpu_affinity(remote.into())
    .spawn();

    let reached = wait_flag(&vmar.allocator.test_pause.reached);
    let hint = vmar.allocator.must_be_free.get_on_cpu(cache_cpu).lock();
    vmar.allocator.test_pause.release();
    // This is a progress observation, not a throughput/time threshold. The
    // existing bounded wait is only a fail-safe: release even on failure so
    // the blocking implementation can finish and join before we assert.
    let completed_while_held = wait_flag(&completed);
    let retained_stale_hint = hint.contains(&address);
    drop(hint);
    drop(controller_guard);
    worker.join();
    assert!(reached, "fixed worker did not reach the acquisition hook");
    assert!(!vmar.allocator.test_pause.timed_out.load(Ordering::Acquire));
    assert!(
        completed_while_held,
        "fixed mapping waited for contended hint maintenance"
    );
    assert!(retained_stale_hint);
    assert_eq!(result.lock().take().unwrap().unwrap(), address);
    assert_eq!(read_byte(&vmar, base), 0x93);
    assert_mapping_perms(
        &vmar,
        base..base + PAGE_SIZE,
        VmPerms::READ | VmPerms::WRITE,
    );
    assert_mapping_perms(&vmar, address..address + PAGE_SIZE, VmPerms::READ);
    assert_eq!(
        vmar.handle_page_fault(&PageFaultInfo::new(address, VmPerms::WRITE))
            .unwrap_err()
            .error(),
        Errno::EACCES
    );
    assert_eq!(vmar.get_mappings_total_size(), before + 2 * PAGE_SIZE);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), rss_before + 1);
    assert_eq!(read_byte(&vmar, address), 0);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), rss_before + 2);
    vmar.remove_mapping(base..address + PAGE_SIZE).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), before);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), rss_before);
}

fn assert_mapping_perms(vmar: &Vmar, range: Range<Vaddr>, perms: VmPerms) {
    let mut covered = 0;
    vmar.for_each_mapping(range.clone(), true, |mapping| {
        assert_eq!(mapping.perms() & VmPerms::ALL_PERMS, perms);
        covered += get_intersected_range(&mapping.range(), &range).len();
    })
    .unwrap();
    assert_eq!(covered, range.len());
}

enum StaleHint {
    Local,
    Remote,
    CoveringRemap,
}

fn stale_hint_preserves_mapping(kind: StaleHint) {
    let vmar = new_vmar();
    let controller_guard = disable_preempt();
    let current = controller_guard.current_cpu();
    let cache_cpu = match kind {
        StaleHint::Local => allocation_cpu(current),
        StaleHint::Remote => remote_cpu(allocation_cpu(current)),
        StaleHint::CoveringRemap => CpuId::bsp(),
    };
    let address = assigned_range_on_cpu(cache_cpu).start + 32 * PAGE_SIZE;
    let occupied = address..address + 2 * PAGE_SIZE;
    let source = address - 2 * PAGE_SIZE;
    let before = vmar.get_mappings_total_size();
    let rss_before = vmar.get_rss_counter(RssType::Anon);
    map(
        &vmar,
        address,
        2,
        OffsetType::FixedNoReplace,
        VmPerms::READ | VmPerms::WRITE,
    )
    .unwrap();
    write_byte(&vmar, address, 0xa3);
    write_byte(&vmar, address + PAGE_SIZE, 0x5c);
    vmar.protect(VmPerms::READ, occupied.clone()).unwrap();
    if matches!(kind, StaleHint::CoveringRemap) {
        map(
            &vmar,
            source,
            1,
            OffsetType::FixedNoReplace,
            VmPerms::READ | VmPerms::WRITE,
        )
        .unwrap();
        write_byte(&vmar, source, 0x72);
    }

    // Simulate skipped fixed-path maintenance. Only this hint is usable, so
    // the first cached attempt must encounter the installed read-only mapping.
    empty_hints(&vmar);
    *vmar.allocator.must_be_free.get_on_cpu(cache_cpu).lock() = occupied.clone();
    let stage = if matches!(kind, StaleHint::CoveringRemap) {
        REMAP_CACHED
    } else {
        CACHED
    };
    // Use the existing one-shot hook as an observation, without a timed pause.
    vmar.allocator.test_pause.release();
    vmar.allocator.test_pause.arm(current, stage);
    let allocated = if matches!(kind, StaleHint::CoveringRemap) {
        vmar.remap(
            source,
            PAGE_SIZE,
            None,
            2 * PAGE_SIZE,
            RemapOldMappingAction::Unmap,
        )
        .unwrap()
    } else {
        vmar.new_map(
            NonZeroUsize::new(2 * PAGE_SIZE).unwrap(),
            VmPerms::READ | VmPerms::WRITE,
        )
        .unwrap()
        .build()
        .unwrap()
    };
    assert!(vmar.allocator.test_pause.reached.load(Ordering::Acquire));
    assert!(!vmar.allocator.test_pause.timed_out.load(Ordering::Acquire));
    let new_range = allocated..allocated + 2 * PAGE_SIZE;
    assert!(!is_intersected(&occupied, &new_range));
    assert_eq!(read_byte(&vmar, address), 0xa3);
    assert_eq!(read_byte(&vmar, address + PAGE_SIZE), 0x5c);
    assert_mapping_perms(&vmar, occupied.clone(), VmPerms::READ);
    for page in [address, address + PAGE_SIZE] {
        // Alien writes deliberately force faults (ptrace semantics). Use a
        // normal fault to test user write rejection instead.
        assert_eq!(
            vmar.handle_page_fault(&PageFaultInfo::new(page, VmPerms::WRITE))
                .unwrap_err()
                .error(),
            Errno::EACCES
        );
    }
    assert_mapping_perms(&vmar, new_range.clone(), VmPerms::READ | VmPerms::WRITE);
    assert_eq!(vmar.get_mappings_total_size(), before + 4 * PAGE_SIZE);
    if matches!(kind, StaleHint::CoveringRemap) {
        assert!(
            vmar.for_each_mapping(source..source + PAGE_SIZE, true, |_| {})
                .is_err()
        );
        assert_eq!(read_byte(&vmar, allocated), 0x72);
        assert_eq!(vmar.get_rss_counter(RssType::Anon), rss_before + 3);
    } else {
        assert_eq!(vmar.get_rss_counter(RssType::Anon), rss_before + 2);
        assert_eq!(read_byte(&vmar, allocated), 0);
        assert_eq!(vmar.get_rss_counter(RssType::Anon), rss_before + 3);
    }
    write_byte(&vmar, allocated, 0x64);
    assert_eq!(read_byte(&vmar, allocated), 0x64);
    assert_eq!(read_byte(&vmar, address), 0xa3);
    assert_eq!(read_byte(&vmar, address + PAGE_SIZE), 0x5c);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), rss_before + 3);
    vmar.remove_mapping(new_range).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), before + 2 * PAGE_SIZE);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), rss_before + 2);
    vmar.remove_mapping(occupied).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), before);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), rss_before);
}

#[ktest]
fn stale_local_hint_preserves_mapping() {
    stale_hint_preserves_mapping(StaleHint::Local);
}

#[ktest]
fn stale_remote_hint_preserves_mapping() {
    stale_hint_preserves_mapping(StaleHint::Remote);
}

#[ktest]
fn stale_covering_remap_hint_preserves_mapping() {
    stale_hint_preserves_mapping(StaleHint::CoveringRemap);
}

fn pending_refill_collision(remap: bool) {
    let vmar = new_vmar();
    let controller_guard = disable_preempt();
    let remote = remote_cpu(controller_guard.current_cpu());
    let cache_cpu = if remap {
        CpuId::bsp()
    } else {
        allocation_cpu(remote)
    };
    let address = assigned_range_on_cpu(cache_cpu).start + 16 * PAGE_SIZE;
    let source = address - 2 * PAGE_SIZE;
    let before = vmar.get_mappings_total_size();
    if remap {
        map(
            &vmar,
            source,
            1,
            OffsetType::FixedNoReplace,
            VmPerms::READ | VmPerms::WRITE,
        )
        .unwrap();
        write_byte(&vmar, source, 0x71);
    }
    empty_hints(&vmar);
    *vmar.allocator.must_be_free.get_on_cpu(cache_cpu).lock() = address..address + PAGE_SIZE;
    vmar.allocator
        .test_pause
        .arm(remote, if remap { REMAP_CACHED } else { CACHED });
    let result = Arc::new(SpinLock::<Option<Result<Vaddr>>, ostd::sync::PreemptDisabled>::new(None));
    let worker_result = result.clone();
    let worker_vmar = vmar.clone_arc();
    let worker = ThreadOptions::new(move || {
        let outcome = if remap {
            worker_vmar.remap(
                source,
                PAGE_SIZE,
                None,
                PAGE_SIZE,
                RemapOldMappingAction::Keep,
            )
        } else {
            worker_vmar
                .new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
                .unwrap()
                .build()
        };
        *worker_result.lock() = Some(outcome);
    })
    .cpu_affinity(remote.into())
    .spawn();
    let reached = wait_flag(&vmar.allocator.test_pause.reached);
    // Use the real slow search to republish a remainder containing the pending
    // address, before a second transaction wins publication at that address.
    let refill_ok = {
        let guard = disable_preempt();
        vmar.allocator
            .try_lock_and_alloc_from(
                &guard,
                vmar.vm_space(),
                &(address - PAGE_SIZE..address + 3 * PAGE_SIZE),
                PAGE_SIZE,
                PAGE_SIZE,
            )
            .is_ok()
    };
    let republished = vmar
        .allocator
        .must_be_free
        .get_on_cpu(cache_cpu)
        .lock()
        .contains(&address);
    let winner = map(
        &vmar,
        address,
        1,
        OffsetType::FixedNoReplace,
        VmPerms::READ | VmPerms::WRITE,
    );
    let winner_written = vmar.write_alien(address, &mut VmReader::from(&[0xa5u8][..]).to_fallible());
    vmar.allocator.test_pause.release();
    drop(controller_guard);
    worker.join();
    assert!(reached && refill_ok && republished);
    assert_eq!(winner_written.unwrap(), 1);
    assert!(!vmar.allocator.test_pause.timed_out.load(Ordering::Acquire));
    assert_eq!(winner.unwrap(), address);
    let allocated = result.lock().take().unwrap().unwrap();
    assert_ne!(allocated, address);
    assert_eq!(read_byte(&vmar, address), 0xa5);
    vmar.for_each_mapping(address..address + PAGE_SIZE, true, |mapping| {
        assert!(mapping.perms().contains(VmPerms::WRITE));
    })
    .unwrap();
    assert_eq!(
        vmar.get_mappings_total_size(),
        before + (if remap { 3 } else { 2 }) * PAGE_SIZE
    );
    if remap {
        assert_eq!(read_byte(&vmar, allocated), 0x71);
        assert_eq!(read_byte(&vmar, source), 0);
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 3);
    } else {
        assert_eq!(vmar.get_rss_counter(RssType::Anon), 1);
    }
}

#[ktest]
fn cached_selection_revalidates_after_refill() {
    pending_refill_collision(false);
}
#[ktest]
fn remap_selection_revalidates_after_refill() {
    pending_refill_collision(true);
}

#[ktest]
fn noreplace_hint_and_half_open_boundaries() {
    let vmar = new_vmar();
    let before = vmar.get_mappings_total_size();
    let base = 0x3ff_000; // Cross a leaf page-table boundary.
    map(
        &vmar,
        base,
        2,
        OffsetType::FixedNoReplace,
        VmPerms::READ | VmPerms::WRITE,
    )
    .unwrap();
    write_byte(&vmar, base, 0x61);
    assert_eq!(
        map(
            &vmar,
            base + PAGE_SIZE,
            2,
            OffsetType::FixedNoReplace,
            VmPerms::READ
        )
        .unwrap_err()
        .error(),
        Errno::EEXIST
    );
    let hint = map(&vmar, base + PAGE_SIZE, 1, OffsetType::Hint, VmPerms::READ).unwrap();
    assert!(hint < base || hint >= base + 2 * PAGE_SIZE);
    map(
        &vmar,
        base + 2 * PAGE_SIZE,
        1,
        OffsetType::FixedNoReplace,
        VmPerms::READ,
    )
    .unwrap();
    assert_eq!(read_byte(&vmar, base), 0x61);
    assert_eq!(vmar.get_mappings_total_size(), before + 4 * PAGE_SIZE);
    map(&vmar, base, 2, OffsetType::Fixed, VmPerms::READ).unwrap();
    assert_eq!(read_byte(&vmar, base), 0);
    assert_eq!(vmar.get_mappings_total_size(), before + 4 * PAGE_SIZE);
    let mut visited = Vec::new();
    vmar.for_each_mapping(base..base + 2 * PAGE_SIZE, true, |mapping| {
        assert!(!mapping.perms().contains(VmPerms::WRITE));
        // Query callbacks return whole mappings, which may extend into the
        // adjacent compatible READ mapping. Check exact queried coverage.
        let range = mapping.range();
        visited.push(range.start.max(base)..range.end.min(base + 2 * PAGE_SIZE));
    })
    .unwrap();
    assert_eq!(visited.len(), 2);
    assert_eq!(
        visited,
        [base..base + PAGE_SIZE, base + PAGE_SIZE..base + 2 * PAGE_SIZE]
    );
    assert_eq!(
        visited.iter().map(|range| range.len()).sum::<usize>(),
        2 * PAGE_SIZE
    );
}

#[ktest]
fn constrained_search_alignment_exact_fit_and_exhaustion() {
    let vmar = new_vmar();
    let base = 0x800_000;
    map(&vmar, base, 4, OffsetType::FixedNoReplace, VmPerms::READ).unwrap();
    vmar.remove_mapping(base + PAGE_SIZE..base + 3 * PAGE_SIZE)
        .unwrap();
    let guard = disable_preempt();
    let (address, cursor) = vmar
        .allocator
        .try_lock_and_alloc_from(
            &guard,
            vmar.vm_space(),
            &(base..base + 4 * PAGE_SIZE),
            2 * PAGE_SIZE,
            PAGE_SIZE,
        )
        .unwrap();
    assert_eq!(address, base + PAGE_SIZE);
    drop(cursor);
    assert!(
        vmar.allocator
            .try_lock_and_alloc_from(
                &guard,
                vmar.vm_space(),
                &(base..base + 4 * PAGE_SIZE),
                2 * PAGE_SIZE,
                2 * PAGE_SIZE
            )
            .is_err()
    );
    drop(guard);
    map(
        &vmar,
        base + PAGE_SIZE,
        2,
        OffsetType::FixedNoReplace,
        VmPerms::READ,
    )
    .unwrap();
    let guard = disable_preempt();
    assert!(
        vmar.allocator
            .try_lock_and_alloc_from(
                &guard,
                vmar.vm_space(),
                &(base..base + 4 * PAGE_SIZE),
                PAGE_SIZE,
                PAGE_SIZE
            )
            .is_err()
    );
}

#[ktest]
fn resize_and_remap_preserve_ranges_data_and_counters() {
    let vmar = new_vmar();
    let before = vmar.get_mappings_total_size();
    let base = 0x5ff_000;
    let dest = 0x9ff_000;
    map(
        &vmar,
        base,
        2,
        OffsetType::FixedNoReplace,
        VmPerms::READ | VmPerms::WRITE,
    )
    .unwrap();
    write_byte(&vmar, base, 0x42);
    vmar.resize_mapping(base, 2 * PAGE_SIZE, 2 * PAGE_SIZE, true)
        .unwrap();
    vmar.resize_mapping(base, 2 * PAGE_SIZE, 3 * PAGE_SIZE, true)
        .unwrap();
    vmar.resize_mapping(base, 3 * PAGE_SIZE, 2 * PAGE_SIZE, true)
        .unwrap();
    assert!(
        vmar.resize_mapping(base + 3 * PAGE_SIZE, PAGE_SIZE, PAGE_SIZE, true)
            .is_err()
    );
    assert_eq!(
        vmar.remap(
            base,
            2 * PAGE_SIZE,
            Some(base + PAGE_SIZE),
            2 * PAGE_SIZE,
            RemapOldMappingAction::Unmap
        )
        .unwrap_err()
        .error(),
        Errno::EINVAL
    );
    assert_eq!(
        vmar.remap(
            base,
            2 * PAGE_SIZE,
            Some(dest),
            3 * PAGE_SIZE,
            RemapOldMappingAction::Unmap
        )
        .unwrap(),
        dest
    );
    assert_eq!(read_byte(&vmar, dest), 0x42);
    assert!(
        vmar.for_each_mapping(base..base + PAGE_SIZE, true, |_| {})
            .is_err()
    );
    assert_eq!(vmar.get_mappings_total_size(), before + 3 * PAGE_SIZE);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), 1);
    vmar.remove_mapping(dest..dest + 3 * PAGE_SIZE).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), before);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), 0);
}

#[cfg(target_arch = "x86_64")]
#[ktest]
fn map32_hint_collision_falls_back_below_limit() {
    let vmar = new_vmar();
    let base = 0x400_000;
    map(
        &vmar,
        base,
        1,
        OffsetType::FixedNoReplace,
        VmPerms::READ | VmPerms::WRITE,
    )
    .unwrap();
    write_byte(&vmar, base, 0x53);
    let allocated = map(&vmar, base, 1, OffsetType::Map32Bit, VmPerms::READ).unwrap();
    assert_ne!(allocated, base);
    assert!(allocated + PAGE_SIZE <= 0x8000_0000);
    assert_eq!(read_byte(&vmar, base), 0x53);
}

// A MAP_32BIT hint is advisory even when it is a valid userspace address above
// the 2 GiB limit. Exercise the public builder rather than the fit predicate.
#[cfg(target_arch = "x86_64")]
#[ktest]
fn map32_hints_respect_upper_bound() {
    const LIMIT: usize = 0x8000_0000;
    let vmar = new_vmar();
    let before = vmar.get_mappings_total_size();
    for (hint, pages, exact_hint) in [
        (0, 1, false),
        (LIMIT, 1, false),
        (LIMIT + PAGE_SIZE, 1, false),
        (LIMIT - PAGE_SIZE, 1, true),
        (LIMIT - PAGE_SIZE, 2, false),
    ] {
        let address = map(&vmar, hint, pages, OffsetType::Map32Bit, VmPerms::READ).unwrap();
        assert!(address >= VMAR_LOWEST_ADDR);
        assert!(address <= LIMIT - pages * PAGE_SIZE);
        if exact_hint {
            assert_eq!(address, hint);
        }
        assert_eq!(vmar.get_mappings_total_size(), before + pages * PAGE_SIZE);
        vmar.remove_mapping(address..address + pages * PAGE_SIZE)
            .unwrap();
        assert_eq!(vmar.get_mappings_total_size(), before);
    }
}

#[cfg(target_arch = "x86_64")]
#[ktest]
fn map32_oversized_request_rejects_without_leaking_mapping() {
    const LIMIT: usize = 0x8000_0000;
    let vmar = new_vmar();
    let before = vmar.get_mappings_total_size();
    // The usable interval starts above zero, so LIMIT bytes cannot fit. The
    // anonymous, unpopulated request needs no physical backing allocation.
    for hint in [0, LIMIT + PAGE_SIZE] {
        assert_eq!(
            map(
                &vmar,
                hint,
                LIMIT / PAGE_SIZE,
                OffsetType::Map32Bit,
                VmPerms::READ,
            )
            .unwrap_err()
            .error(),
            Errno::ENOMEM
        );
        assert_eq!(vmar.get_mappings_total_size(), before);
        let address = map(&vmar, 0, 1, OffsetType::Map32Bit, VmPerms::READ).unwrap();
        assert!(address >= VMAR_LOWEST_ADDR && address <= LIMIT - PAGE_SIZE);
        vmar.remove_mapping(address..address + PAGE_SIZE).unwrap();
        assert_eq!(vmar.get_mappings_total_size(), before);
    }
}

#[ktest]
fn hint_success_and_unrestricted_exhaustion_preserve_mappings() {
    let vmar = new_vmar();
    let before = vmar.get_mappings_total_size();
    let hint = 0x800_000;
    assert_eq!(
        map(
            &vmar,
            hint,
            1,
            OffsetType::Hint,
            VmPerms::READ | VmPerms::WRITE,
        )
        .unwrap(),
        hint
    );
    write_byte(&vmar, hint, 0x6b);
    // No address range can fit this request: the usable space starts at
    // VMAR_LOWEST_ADDR. All allocator fit checks reject before taking PT locks.
    assert_eq!(
        vmar.new_map(NonZeroUsize::new(VMAR_CAP_ADDR).unwrap(), VmPerms::READ)
            .unwrap()
            .build()
            .unwrap_err()
            .error(),
        Errno::ENOMEM
    );
    assert_eq!(vmar.get_mappings_total_size(), before + PAGE_SIZE);
    assert_eq!(read_byte(&vmar, hint), 0x6b);
    let address = vmar
        .new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
        .unwrap()
        .build()
        .unwrap();
    assert_ne!(address, hint);
    vmar.remove_mapping(address..address + PAGE_SIZE).unwrap();
    vmar.remove_mapping(hint..hint + PAGE_SIZE).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), before);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), 0);
}

#[ktest]
fn alloc_from_free_range_accepts_exact_fit() {
    assert_eq!(
        alloc_from_free_range(0x4000..0x8000, 0x4000, PAGE_SIZE).unwrap(),
        0x4000
    );
}

#[ktest]
fn alloc_from_free_range_rejects_too_small_range() {
    assert!(alloc_from_free_range(0x4000..0x7000, 0x4000, PAGE_SIZE).is_err());
}

#[ktest]
fn competing_noreplace_has_one_winner() {
    let vmar = new_vmar();
    let controller_guard = disable_preempt();
    let remote = remote_cpu(controller_guard.current_cpu());
    let base = 0x600_000;
    let before = vmar.get_mappings_total_size();
    vmar.allocator.test_pause.arm(remote, FIXED);
    let result = Arc::new(SpinLock::<Option<Result<Vaddr>>, ostd::sync::PreemptDisabled>::new(None));
    let worker_result = result.clone();
    let worker_vmar = vmar.clone_arc();
    let worker = ThreadOptions::new(move || {
        *worker_result.lock() = Some(map(
            &worker_vmar,
            base,
            2,
            OffsetType::FixedNoReplace,
            VmPerms::READ,
        ));
    })
    .cpu_affinity(remote.into())
    .spawn();
    let reached = wait_flag(&vmar.allocator.test_pause.reached);
    let winner = map(
        &vmar,
        base,
        2,
        OffsetType::FixedNoReplace,
        VmPerms::READ | VmPerms::WRITE,
    );
    let written = vmar.write_alien(base, &mut VmReader::from(&[0x98u8][..]).to_fallible());
    vmar.allocator.test_pause.release();
    drop(controller_guard);
    worker.join();
    assert!(reached);
    assert!(!vmar.allocator.test_pause.timed_out.load(Ordering::Acquire));
    assert_eq!(winner.unwrap(), base);
    assert_eq!(written.unwrap(), 1);
    assert_eq!(
        result.lock().take().unwrap().unwrap_err().error(),
        Errno::EEXIST
    );
    assert_eq!(read_byte(&vmar, base), 0x98);
    assert_eq!(vmar.get_mappings_total_size(), before + 2 * PAGE_SIZE);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), 1);
}

fn fork_with_pending_allocation_preserves_cow(stage: usize) {
    let vmar = new_vmar();
    let controller_guard = disable_preempt();
    let remote = remote_cpu(controller_guard.current_cpu());
    let base = 0x700_000;
    map(
        &vmar,
        base,
        1,
        OffsetType::FixedNoReplace,
        VmPerms::READ | VmPerms::WRITE,
    )
    .unwrap();
    write_byte(&vmar, base, 0x87);
    vmar.allocator.test_pause.arm(remote, stage);
    let worker_vmar = vmar.clone_arc();
    let completed = Arc::new(AtomicBool::new(false));
    let worker_completed = completed.clone();
    let worker = ThreadOptions::new(move || {
        let result = if stage == FIXED {
            worker_vmar
                .resize_mapping(base, PAGE_SIZE, 2 * PAGE_SIZE, true)
                .map(|_| base)
        } else {
            worker_vmar
                .new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
                .unwrap()
                .build()
        };
        worker_completed.store(result.is_ok(), Ordering::Release);
    })
    .cpu_affinity(remote.into())
    .spawn();
    let reached = wait_flag(&vmar.allocator.test_pause.reached);
    let child = Vmar::fork_from(&vmar);
    vmar.allocator.test_pause.release();
    drop(controller_guard);
    worker.join();
    assert!(reached);
    assert!(!vmar.allocator.test_pause.timed_out.load(Ordering::Acquire));
    assert!(completed.load(Ordering::Acquire));
    let child = child.unwrap();
    assert_eq!(read_byte(&child, base), 0x87);
    write_byte(&vmar, base, 0x29);
    assert_eq!(read_byte(&child, base), 0x87);
    assert_eq!(read_byte(&vmar, base), 0x29);
}

#[ktest]
fn fork_with_pending_selection_preserves_cow() {
    fork_with_pending_allocation_preserves_cow(CACHED);
}

#[ktest]
fn fork_with_pending_resize_preserves_cow() {
    fork_with_pending_allocation_preserves_cow(FIXED);
}

#[ktest]
fn exhausted_current_hint_uses_other_hint_then_slow_search() {
    let vmar = new_vmar();
    let controller_guard = disable_preempt();
    let remote = remote_cpu(allocation_cpu(controller_guard.current_cpu()));
    empty_hints(&vmar);
    // Keep the current CPU stable while consuming a different CPU cache.
    let other_address = assigned_range_on_cpu(allocation_cpu(remote)).start + 32 * PAGE_SIZE;
    *vmar.allocator.must_be_free.get_on_cpu(remote).lock() =
        other_address..other_address + PAGE_SIZE;
    let allocated = vmar
        .new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(allocated, other_address);
    empty_hints(&vmar);
    let second = vmar
        .new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
        .unwrap()
        .build()
        .unwrap();
    assert_ne!(second, allocated);
    vmar.for_each_mapping(allocated..allocated + PAGE_SIZE, true, |_| {})
        .unwrap();
    vmar.for_each_mapping(second..second + PAGE_SIZE, true, |_| {})
        .unwrap();
}

#[ktest]
fn fixed_range_crosses_assigned_cache_boundary() {
    let vmar = new_vmar();
    let boundary_cpu = all_cpus()
        .find(|cpu| *cpu != CpuId::bsp())
        .expect("run cache-boundary test with >=2 CPUs");
    if cfg!(feature = "single_vmar_alloc") {
        return;
    }
    let boundary = assigned_range_on_cpu(boundary_cpu).start;
    let before = vmar.get_mappings_total_size();
    map(
        &vmar,
        boundary - PAGE_SIZE,
        2,
        OffsetType::FixedNoReplace,
        VmPerms::READ | VmPerms::WRITE,
    )
    .unwrap();
    write_byte(&vmar, boundary - PAGE_SIZE, 0x31);
    write_byte(&vmar, boundary, 0x32);
    assert_eq!(read_byte(&vmar, boundary - PAGE_SIZE), 0x31);
    assert_eq!(read_byte(&vmar, boundary), 0x32);
    assert_eq!(vmar.get_mappings_total_size(), before + 2 * PAGE_SIZE);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), 2);
    vmar.remove_mapping(boundary - PAGE_SIZE..boundary + PAGE_SIZE)
        .unwrap();
    assert_eq!(vmar.get_mappings_total_size(), before);
    assert_eq!(vmar.get_rss_counter(RssType::Anon), 0);
}
