// SPDX-License-Identifier: MPL-2.0

//! Regression tests using real VMAR mappings, admission, metadata and counters.

use core::{
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use ostd::{
    cpu::{CpuId, PinCurrentCpu, all_cpus, num_cpus},
    prelude::ktest,
    task::disable_preempt,
    util::id_set::Id,
};

use super::*;
use crate::{
    fs::pseudofs::SockFs,
    process::{
        ProcessVm,
        rlimit::{RLIM_INFINITY, RLimit64},
    },
    thread::kernel_thread::ThreadOptions,
    vm::{
        perms::VmPerms,
        vmar::{OffsetType, VMAR_CAP_ADDR, VmarHandle},
    },
};

pub(super) const AFTER_UNMAP_PT: usize = 1;
pub(super) const AFTER_SHRINK_PT: usize = 2;
pub(super) const BEFORE_MAP_PT: usize = 3;
const SPIN_BUDGET: usize = 100_000_000;
const ADDR: usize = 0x20_0000;
const DEST: usize = 0x80_0000;

/// One-shot, per-VMAR, CPU-selected pause; no production state is emitted.
/// It never retains accounting guards. After-release hooks also retain no PT
/// or allocator guard, so a fork can complete while the worker is paused.
pub(super) struct Pause {
    stage: AtomicUsize,
    cpu: AtomicUsize,
    reached: AtomicBool,
    released: AtomicBool,
    departed: AtomicBool,
    timed_out: AtomicBool,
}

impl Pause {
    pub(super) const fn new() -> Self {
        Self {
            stage: AtomicUsize::new(0),
            cpu: AtomicUsize::new(usize::MAX),
            reached: AtomicBool::new(false),
            released: AtomicBool::new(false),
            departed: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
        }
    }

    fn arm(&self, cpu: CpuId, stage: usize) {
        self.cpu.store(cpu.as_usize(), Ordering::Relaxed);
        self.stage.store(stage, Ordering::Release);
    }

    pub(super) fn hit(&self, stage: usize) {
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
        if !wait(&self.released) {
            self.timed_out.store(true, Ordering::Release);
        }
        self.departed.store(true, Ordering::Release);
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
    }
}

fn wait(flag: &AtomicBool) -> bool {
    for _ in 0..SPIN_BUDGET {
        if flag.load(Ordering::Acquire) {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn other_cpu(cpu: CpuId) -> CpuId {
    all_cpus()
        .find(|other| *other != cpu)
        .expect("run SMP accounting test with >=2 CPUs")
}

fn on_cpu<T: Send + 'static>(cpu: CpuId, action: impl FnOnce() -> T + Send + 'static) -> T {
    crate::thread::init();
    let output = Arc::new(SpinLock::<Option<T>, ostd::sync::PreemptDisabled>::new(None));
    let worker_output = output.clone();
    let worker = ThreadOptions::new(move || {
        // Construct/map outside the slot lock. Affinity fixes all initial
        // charges, including the reserved stack, on the selected CPU.
        let value = action();
        *worker_output.lock() = Some(value);
    })
    .cpu_affinity(cpu.into())
    .spawn();
    worker.join();
    let value = output.lock().take().unwrap();
    value
}

fn new_vmar() -> VmarHandle {
    crate::thread::init();
    crate::time::clocks::init_for_ktest();
    crate::util::random::init();
    let vmar = VmarHandle::new(ProcessVm::new(SockFs::new_path())).unwrap();
    vmar.process_vm().map_and_init_heap_for_ktest(&vmar).unwrap();
    vmar
}

fn map(vmar: &Vmar, addr: usize, pages: usize, limit: &RLimit64) -> Result<Vaddr> {
    vmar.new_map(
        NonZeroUsize::new(pages * PAGE_SIZE).unwrap(),
        VmPerms::READ | VmPerms::WRITE,
    )?
    .offset(addr, OffsetType::FixedNoReplace)
    .build_with_rlimit_as(limit)
}

fn metadata_totals(vmar: &Vmar) -> (usize, usize) {
    let mut bytes = 0;
    vmar.for_each_mapping(0..VMAR_CAP_ADDR, false, |mapping| {
        bytes += mapping.range().len();
    })
    .unwrap();

    // A partially resident mapping can have an unknown metadata frame count
    // after splitting. Count actual RAM PTEs independently of that hint.
    // The metadata iteration has released its cursor before this acquisition.
    let guard = disable_preempt();
    let mut cursor = vmar.vm_space().cursor(&guard, &(0..VMAR_CAP_ADDR)).unwrap();
    let mut frames = 0;
    while let Some(address) = cursor.find_next(VMAR_CAP_ADDR) {
        let end = cursor.cur_va_range().end.min(VMAR_CAP_ADDR);
        if matches!(cursor.query(), ostd::mm::vm_space::VmQueriedItem::MappedRam { .. }) {
            // The slot spans one base or huge page; I/O PTEs do not count.
            frames += (end - address) / PAGE_SIZE;
        }
        if end == VMAR_CAP_ADDR {
            break;
        }
        cursor.jump(end).unwrap();
    }
    (bytes, frames)
}

fn assert_consistent(vmar: &Vmar) {
    let (bytes, frames) = metadata_totals(vmar);
    assert_eq!(vmar.get_mappings_total_size(), bytes);
    assert_eq!(
        vmar.get_rss_counter(RssType::Anon) + vmar.get_rss_counter(RssType::File),
        frames
    );
}

fn write_byte(vmar: &Vmar, addr: usize, value: u8) {
    assert_eq!(
        vmar.write_alien(addr, &mut VmReader::from(&[value][..]).to_fallible())
            .unwrap(),
        1
    );
}

fn read_byte(vmar: &Vmar, addr: usize) -> u8 {
    let mut bytes = [0u8];
    assert_eq!(
        vmar.read_alien(addr, &mut VmWriter::from(&mut bytes[..]).to_fallible())
            .unwrap(),
        1
    );
    bytes[0]
}

fn present(vmar: &Vmar, addr: usize) -> bool {
    let mut found = false;
    vmar.for_each_mapping(addr..addr + PAGE_SIZE, false, |_| found = true)
        .unwrap();
    found
}

#[ktest]
fn finite_capacity_rejection_and_byte_remainder() {
    let vmar = new_vmar();
    let base = vmar.get_mappings_total_size();
    let limit = RLimit64::new_for_accounting_test((base + 3 * PAGE_SIZE - 1) as u64);
    // A single CPU can consume the whole budget, including unpopulated pages.
    map(&vmar, ADDR, 2, &limit).unwrap();
    assert_eq!(
        map(&vmar, DEST, 1, &limit).unwrap_err().error(),
        Errno::ENOMEM
    );
    assert!(!present(&vmar, DEST));
    assert_eq!(vmar.get_mappings_total_size(), base + 2 * PAGE_SIZE);
    limit.set_cur_for_accounting_test((base + 3 * PAGE_SIZE) as u64);
    map(&vmar, DEST, 1, &limit).unwrap();
    assert_consistent(&vmar);
    vmar.remove_mapping(ADDR..ADDR + 2 * PAGE_SIZE).unwrap();
    vmar.remove_mapping(DEST..DEST + PAGE_SIZE).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), base);
    limit.set_cur_for_accounting_test(0);
    assert_eq!(
        map(&vmar, ADDR, 1, &limit).unwrap_err().error(),
        Errno::ENOMEM
    );
    assert_consistent(&vmar);
}

#[ktest]
fn lowered_limit_on_other_cpu_rejects_growth() {
    let (vmar, base) = on_cpu(CpuId::bsp(), || {
        let vmar = new_vmar();
        let base = vmar.get_mappings_total_size();
        map(
            &vmar,
            ADDR,
            2,
            &RLimit64::new_for_accounting_test(RLIM_INFINITY),
        )
        .unwrap();
        (vmar, base)
    });
    let remote = other_cpu(CpuId::bsp());
    for current_limit in [base + 2 * PAGE_SIZE, base + PAGE_SIZE] {
        let worker_vmar = vmar.clone_handle();
        let result = Arc::new(AtomicUsize::new(0));
        let worker_result = result.clone();
        let worker = ThreadOptions::new(move || {
            let limit = RLimit64::new_for_accounting_test(current_limit as u64);
            let outcome = map(&worker_vmar, DEST, 1, &limit);
            worker_result.store(
                match outcome {
                    Err(e) if e.error() == Errno::ENOMEM => 1,
                    _ => 2,
                },
                Ordering::Release,
            );
        })
        .cpu_affinity(remote.into())
        .spawn();
        worker.join();
        assert_eq!(result.load(Ordering::Acquire), 1);
        assert!(!present(&vmar, DEST));
        assert_consistent(&vmar);
    }
    vmar.remove_mapping(ADDR..ADDR + 2 * PAGE_SIZE).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), base);
}

#[ktest]
fn cross_cpu_unmap_debt_preserves_capacity() {
    let (vmar, base) = on_cpu(CpuId::bsp(), || {
        let vmar = new_vmar();
        let base = vmar.get_mappings_total_size();
        map(
            &vmar,
            ADDR,
            2,
            &RLimit64::new_for_accounting_test(RLIM_INFINITY),
        )
        .unwrap();
        (vmar, base)
    });
    let limit = RLimit64::new_for_accounting_test((base + 2 * PAGE_SIZE) as u64);
    let worker_vmar = vmar.clone_handle();
    let worker = ThreadOptions::new(move || {
        worker_vmar
            .remove_mapping(ADDR..ADDR + 2 * PAGE_SIZE)
            .unwrap()
    })
    .cpu_affinity(other_cpu(CpuId::bsp()).into())
    .spawn();
    worker.join();
    assert_eq!(vmar.get_mappings_total_size(), base);
    // Debt must neither leak capacity nor permit one extra byte/page.
    map(&vmar, ADDR, 2, &limit).unwrap();
    assert_eq!(
        map(&vmar, DEST, 1, &limit).unwrap_err().error(),
        Errno::ENOMEM
    );
    vmar.remove_mapping(ADDR..ADDR + 2 * PAGE_SIZE).unwrap();
    assert_consistent(&vmar);
}

#[ktest]
fn concurrent_finite_admission_has_one_winner() {
    let vmar = new_vmar();
    let base = vmar.get_mappings_total_size();
    let limit = Arc::new(RLimit64::new_for_accounting_test((base + PAGE_SIZE) as u64));
    let start = Arc::new(AtomicBool::new(false));
    let outcomes = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let cpus = [CpuId::bsp(), other_cpu(CpuId::bsp())];
    // Distinct halves also use distinct allocator caches in ordinary SMP mode.
    let addresses = [ADDR, (VMAR_CAP_ADDR / 2) & !(PAGE_SIZE - 1)];
    let workers: Vec<_> = cpus
        .into_iter()
        .enumerate()
        .map(|(i, cpu)| {
            let worker_vmar = vmar.clone_handle();
            let worker_limit = limit.clone();
            let worker_start = start.clone();
            let worker_outcomes = outcomes.clone();
            ThreadOptions::new(move || {
                if !wait(&worker_start) {
                    worker_outcomes[i].store(3, Ordering::Release);
                    return;
                }
                let outcome = map(&worker_vmar, addresses[i], 1, &worker_limit);
                worker_outcomes[i].store(
                    match outcome {
                        Ok(_) => 1,
                        Err(e) if e.error() == Errno::ENOMEM => 2,
                        _ => 3,
                    },
                    Ordering::Release,
                );
            })
            .cpu_affinity(cpu.into())
            .spawn()
        })
        .collect();
    start.store(true, Ordering::Release);
    for worker in workers {
        worker.join();
    }
    let result = [
        outcomes[0].load(Ordering::Acquire),
        outcomes[1].load(Ordering::Acquire),
    ];
    let winners = result.iter().filter(|r| **r == 1).count();
    let rejections = result.iter().filter(|r| **r == 2).count();
    let total = vmar.get_mappings_total_size();
    for addr in addresses {
        vmar.remove_mapping(addr..addr + PAGE_SIZE).unwrap();
    }
    assert_eq!(winners, 1);
    assert_eq!(rejections, 1);
    assert_eq!(total, base + PAGE_SIZE);
    assert_eq!(vmar.get_mappings_total_size(), base);
    assert_consistent(&vmar);
}

#[ktest]
fn ordinary_moved_remap_charges_only_growth() {
    for (old_pages, new_pages) in [(2, 2), (2, 3), (3, 2)] {
        for overwrite in [false, true] {
            let vmar = new_vmar();
            let base = vmar.get_mappings_total_size();
            let limit = RLimit64::new_for_accounting_test(RLIM_INFINITY);
            map(&vmar, ADDR, old_pages, &limit).unwrap();
            write_byte(&vmar, ADDR, 0x5a);
            if overwrite {
                map(&vmar, DEST, 1, &limit).unwrap();
                write_byte(&vmar, DEST, 0x33);
            }
            assert_eq!(
                vmar.remap(
                    ADDR,
                    old_pages * PAGE_SIZE,
                    Some(DEST),
                    new_pages * PAGE_SIZE,
                    RemapOldMappingAction::Unmap
                )
                .unwrap(),
                DEST
            );
            assert!(!present(&vmar, ADDR));
            assert_eq!(read_byte(&vmar, DEST), 0x5a);
            assert_eq!(vmar.get_mappings_total_size(), base + new_pages * PAGE_SIZE);
            assert_consistent(&vmar);
            vmar.remove_mapping(DEST..DEST + new_pages * PAGE_SIZE)
                .unwrap();
            assert_eq!(vmar.get_mappings_total_size(), base);
        }
    }
}

#[ktest]
fn keep_remap_resize_and_discard_preserve_accounting() {
    let vmar = new_vmar();
    let base = vmar.get_mappings_total_size();
    let limit = RLimit64::new_for_accounting_test(RLIM_INFINITY);
    map(&vmar, ADDR, 2, &limit).unwrap();
    write_byte(&vmar, ADDR, 0x5a);
    vmar.remap(
        ADDR,
        2 * PAGE_SIZE,
        Some(DEST),
        2 * PAGE_SIZE,
        RemapOldMappingAction::Keep,
    )
    .unwrap();
    assert_eq!(read_byte(&vmar, DEST), 0x5a);
    assert_eq!(read_byte(&vmar, ADDR), 0);
    assert_eq!(vmar.get_mappings_total_size(), base + 4 * PAGE_SIZE);
    vmar.resize_mapping(DEST, 2 * PAGE_SIZE, 3 * PAGE_SIZE, true)
        .unwrap();
    vmar.resize_mapping(DEST, 3 * PAGE_SIZE, PAGE_SIZE, true)
        .unwrap();
    assert_eq!(vmar.get_mappings_total_size(), base + 3 * PAGE_SIZE);
    vmar.discard_pages(DEST..DEST + PAGE_SIZE).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), base + 3 * PAGE_SIZE);
    assert_consistent(&vmar);
    vmar.remove_mapping(ADDR..ADDR + 2 * PAGE_SIZE).unwrap();
    vmar.remove_mapping(DEST..DEST + PAGE_SIZE).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), base);
}

fn fork_after_removal(stage: usize) {
    let vmar = new_vmar();
    let limit = RLimit64::new_for_accounting_test(RLIM_INFINITY);
    map(&vmar, ADDR, 2, &limit).unwrap();
    write_byte(&vmar, ADDR + PAGE_SIZE, 0x5a);
    let controller_guard = disable_preempt();
    let remote = other_cpu(controller_guard.current_cpu());
    vmar.accounting_pause.arm(remote, stage);
    let worker_vmar = vmar.clone_handle();
    let result = Arc::new(AtomicBool::new(false));
    let worker_result = result.clone();
    let worker = ThreadOptions::new(move || {
        let outcome = if stage == AFTER_UNMAP_PT {
            worker_vmar.remove_mapping(ADDR + PAGE_SIZE..ADDR + 2 * PAGE_SIZE)
        } else {
            worker_vmar.resize_mapping(ADDR, 2 * PAGE_SIZE, PAGE_SIZE, true)
        };
        worker_result.store(outcome.is_ok(), Ordering::Release);
    })
    .cpu_affinity(remote.into())
    .spawn();
    let reached = wait(&vmar.accounting_pause.reached);
    // Defer every assertion until the worker is released and joined. Capture
    // Result rather than unwrapping while it may still be paused.
    let child = if reached {
        Some(Vmar::fork_from(&vmar))
    } else {
        None
    };
    vmar.accounting_pause.release();
    drop(controller_guard);
    worker.join();
    assert!(reached);
    assert!(!vmar.accounting_pause.timed_out.load(Ordering::Acquire));
    assert!(result.load(Ordering::Acquire));
    let child = child.unwrap().unwrap();
    assert!(!present(&child, ADDR + PAGE_SIZE));
    assert_consistent(&vmar);
    assert_consistent(&child);
    assert_eq!(
        child.get_mappings_total_size(),
        vmar.get_mappings_total_size()
    );
}

#[ktest]
fn fork_after_unmap_pt_release_has_no_phantom_charge() {
    fork_after_removal(AFTER_UNMAP_PT);
}

#[ktest]
fn fork_after_shrink_pt_release_has_no_phantom_charge() {
    fork_after_removal(AFTER_SHRINK_PT);
}

#[ktest]
fn separately_scheduled_limit_update_before_pt_release() {
    for raise in [false, true] {
        let vmar = new_vmar();
        let base = vmar.get_mappings_total_size();
        let initial = if raise { base } else { base + PAGE_SIZE };
        let limit = Arc::new(RLimit64::new_for_accounting_test(initial as u64));
        let guard = disable_preempt();
        let remote = other_cpu(guard.current_cpu());
        vmar.accounting_pause.arm(remote, BEFORE_MAP_PT);
        let cursor = vmar
            .vm_space()
            .cursor_mut(&guard, &(0..VMAR_CAP_ADDR))
            .unwrap();
        let worker_vmar = vmar.clone_handle();
        let worker_limit = limit.clone();
        let result = Arc::new(AtomicUsize::new(0));
        let worker_result = result.clone();
        let worker = ThreadOptions::new(move || {
            let outcome = map(&worker_vmar, ADDR, 1, &worker_limit);
            worker_result.store(
                match outcome {
                    Ok(_) => 1,
                    Err(e) if e.error() == Errno::ENOMEM => 2,
                    _ => 3,
                },
                Ordering::Release,
            );
        })
        .cpu_affinity(remote.into())
        .spawn();
        let reached = wait(&vmar.accounting_pause.reached);
        vmar.accounting_pause.release();
        let departed = wait(&vmar.accounting_pause.departed);
        // The builder has entered on another CPU. Its covering PT is still
        // held here; the executing test thread changes the live limit before
        // allowing admission. No callback writes this value in the builder.
        let updated = if raise { base + PAGE_SIZE } else { base };
        limit.set_cur_for_accounting_test(updated as u64);
        drop(cursor);
        drop(guard);
        worker.join();
        assert!(reached && departed);
        assert!(!vmar.accounting_pause.timed_out.load(Ordering::Acquire));
        assert_eq!(result.load(Ordering::Acquire), if raise { 1 } else { 2 });
        assert_eq!(present(&vmar, ADDR), raise);
        vmar.remove_mapping(ADDR..ADDR + PAGE_SIZE).unwrap();
        assert_eq!(vmar.get_mappings_total_size(), base);
        assert_consistent(&vmar);
    }
}

#[ktest]
fn clear_and_fork_accounting_match_metadata() {
    let vmar = new_vmar();
    let limit = RLimit64::new_for_accounting_test(RLIM_INFINITY);
    map(&vmar, ADDR, 1, &limit).unwrap();
    write_byte(&vmar, ADDR, 0x42);
    let child = Vmar::fork_from(&vmar).unwrap();
    assert_consistent(&child);
    assert_eq!(read_byte(&child, ADDR), 0x42);
    child.clear();
    assert_eq!(child.get_mappings_total_size(), 0);
    assert_consistent(&child);
    assert_eq!(read_byte(&vmar, ADDR), 0x42);
    assert_consistent(&vmar);
}

#[ktest]
fn distributed_nonpage_limit_never_admits_last_page() {
    let parent = new_vmar();
    // The old algorithm spreads this inherited usage across all shards.
    let vmar = Vmar::fork_from(&parent).unwrap();
    let base = vmar.get_mappings_total_size();
    let cpu_count = num_cpus();
    let limit = Arc::new(RLimit64::new_for_accounting_test(
        (base + cpu_count * PAGE_SIZE - 1) as u64,
    ));
    let outcomes = Arc::new(AtomicUsize::new(0));
    for cpu in all_cpus() {
        let worker_vmar = vmar.clone_handle();
        let worker_limit = limit.clone();
        let worker_outcomes = outcomes.clone();
        let worker = ThreadOptions::new(move || {
            let addr = ADDR + cpu.as_usize() * 2 * PAGE_SIZE;
            let outcome = map(&worker_vmar, addr, 1, &worker_limit);
            match outcome {
                Ok(_) => {
                    worker_outcomes.fetch_add(1, Ordering::AcqRel);
                }
                Err(e) => assert_eq!(e.error(), Errno::ENOMEM),
            }
        })
        .cpu_affinity(cpu.into())
        .spawn();
        worker.join();
    }
    let admitted = outcomes.load(Ordering::Acquire);
    let total = vmar.get_mappings_total_size();
    vmar.remove_mapping(ADDR..ADDR + cpu_count * 2 * PAGE_SIZE)
        .unwrap();
    assert_eq!(admitted, cpu_count - 1);
    assert_eq!(total, base + (cpu_count - 1) * PAGE_SIZE);
    assert_eq!(vmar.get_mappings_total_size(), base);
    assert_consistent(&vmar);
}

// Candidate-only bounded debt seeds exercise the production abstraction, not
// a duplicate arithmetic model. The paired old source omits these two tests.
#[ktest]
fn positive_shard_overflow_normalizes_without_losing_charge() {
    assert!(num_cpus() >= 2);
    let vmar = new_vmar();
    let base = vmar.get_mappings_total_size();
    {
        let guard = disable_preempt();
        let _cursor = vmar
            .vm_space()
            .cursor_mut(&guard, &(0..VMAR_CAP_ADDR))
            .unwrap();
        let positive = isize::MAX - PAGE_SIZE as isize;
        vmar.mapped_vm_size
            .seed_debt_for_test(&[positive, base as isize - positive]);
    }
    let worker_vmar = vmar.clone_handle();
    let worker = ThreadOptions::new(move || {
        map(
            &worker_vmar,
            ADDR,
            2,
            &RLimit64::new_for_accounting_test(RLIM_INFINITY),
        )
        .unwrap();
    })
    .cpu_affinity(CpuId::bsp().into())
    .spawn();
    worker.join();
    assert_eq!(vmar.get_mappings_total_size(), base + 2 * PAGE_SIZE);
    assert_consistent(&vmar);
    vmar.remove_mapping(ADDR..ADDR + 2 * PAGE_SIZE).unwrap();
    assert_eq!(vmar.get_mappings_total_size(), base);
}

#[ktest]
fn negative_shard_overflow_normalizes_without_losing_debt() {
    assert!(num_cpus() >= 3);
    let vmar = new_vmar();
    let limit = RLimit64::new_for_accounting_test(RLIM_INFINITY);
    map(&vmar, ADDR, 2, &limit).unwrap();
    let total = vmar.get_mappings_total_size();
    {
        let guard = disable_preempt();
        let _cursor = vmar
            .vm_space()
            .cursor_mut(&guard, &(0..VMAR_CAP_ADDR))
            .unwrap();
        let negative = isize::MIN + PAGE_SIZE as isize;
        let residue = (total as i128 - negative as i128 - isize::MAX as i128) as isize;
        vmar.mapped_vm_size
            .seed_debt_for_test(&[negative, isize::MAX, residue]);
    }
    let worker_vmar = vmar.clone_handle();
    let worker = ThreadOptions::new(move || {
        worker_vmar
            .remove_mapping(ADDR..ADDR + 2 * PAGE_SIZE)
            .unwrap()
    })
    .cpu_affinity(CpuId::bsp().into())
    .spawn();
    worker.join();
    assert_eq!(vmar.get_mappings_total_size(), total - 2 * PAGE_SIZE);
    assert_consistent(&vmar);
    limit.set_cur_for_accounting_test(total as u64);
    map(&vmar, ADDR, 2, &limit).unwrap();
    vmar.remove_mapping(ADDR..ADDR + 2 * PAGE_SIZE).unwrap();
    assert_consistent(&vmar);
}
