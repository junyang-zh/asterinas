// SPDX-License-Identifier: MPL-2.0

//! Exact mapped-byte accounting with CPU-local unlimited updates.

use core::sync::atomic::{AtomicBool, Ordering};

use osdk_heap_allocator::{CpuLocalBox, alloc_cpu_local};
use ostd::{
    cpu::{CpuId, all_cpus},
    sync::{PreemptDisabled, SpinLock, SpinLockGuard},
};

use crate::{prelude::*, process::rlimit::RLIM_INFINITY};

/// Signed shards retain cross-CPU unmap debt without imposing per-CPU quotas.
///
/// Lock order: optional covering PT, gate, then one shard. Local updates drop
/// their shard before waiting for the gate. Accounting never acquires a PT,
/// allocator or rmap lock, allocates, or performs I/O while holding a guard.
pub(super) struct MappingSize {
    shards: CpuLocalBox<SpinLock<isize>>,
    gate: SpinLock<()>,
    frozen: AtomicBool,
}

impl MappingSize {
    pub(super) fn new(total: usize) -> Result<Self> {
        // A complete VMAR is smaller than isize::MAX. Only individual shard
        // debt can approach a signed extreme through repeated cross-CPU churn.
        let total = isize::try_from(total).expect("mapped address space exceeds signed range");
        Ok(Self {
            shards: alloc_cpu_local(|cpu| {
                SpinLock::new(if cpu == CpuId::bsp() { total } else { 0 })
            })?,
            gate: SpinLock::new(()),
            frozen: AtomicBool::new(false),
        })
    }

    pub(super) fn add(&self, cpu: CpuId, size: usize, limit: u64) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let size = isize::try_from(size).map_err(|_| Errno::ENOMEM)?;
        if limit == RLIM_INFINITY {
            self.update_local(cpu, size);
            return Ok(());
        }

        let frozen = self.freeze();
        let total = frozen.total() + size as i128;
        if total > limit as i128 {
            return_errno_with_message!(Errno::ENOMEM, "the new mapping size exceeds the limit");
        }
        frozen.commit(cpu, size, total);
        Ok(())
    }

    pub(super) fn subtract(&self, cpu: CpuId, delta: isize) {
        debug_assert!(delta <= 0);
        if delta != 0 {
            self.update_local(cpu, delta);
        }
    }

    pub(super) fn total(&self) -> usize {
        usize::try_from(self.freeze().total()).expect("invalid mapped address space total")
    }

    pub(super) fn clear(&self) {
        self.freeze().normalize(0);
    }

    fn update_local(&self, cpu: CpuId, delta: isize) {
        loop {
            let mut shard = self.shards.get_on_cpu(cpu).lock();
            // This load MUST occur under the shard lock. After a frozen scan
            // visits this shard, its Release unlock happens-before a later
            // lock's Acquire and this load, which must then observe the freeze
            // (or a later thaw). Writers on unvisited shards finish before the
            // scan obtains their lock. Thus all visited values coexist at the
            // last visit, despite retaining only one guard at a time.
            if self.frozen.load(Ordering::Acquire) {
                drop(shard);
                drop(self.gate.lock());
                continue;
            }
            if let Some(new) = shard.checked_add(delta) {
                *shard = new;
                return;
            }
            drop(shard);
            // Retry the pending delta exactly once against a fresh stable sum;
            // another updater may have completed since the local overflow.
            let frozen = self.freeze();
            frozen.normalize(frozen.total() + delta as i128);
            return;
        }
    }

    fn freeze(&self) -> Frozen<'_> {
        let gate = self.gate.lock();
        self.frozen.store(true, Ordering::Release);
        // Install RAII before scanning, so even an unwinding scan thaws.
        let mut frozen = Frozen {
            accounting: self,
            _gate: gate,
            total: 0,
        };
        // At most usize::MAX signed machine words fit in this allocation;
        // their sum fits i128 on all supported (64-bit) architectures.
        frozen.total = all_cpus()
            .map(|cpu| *self.shards.get_on_cpu(cpu).lock() as i128)
            .sum();
        // A returned Frozen has visited every shard and is fully quiescent.
        frozen
    }
}

struct Frozen<'a> {
    accounting: &'a MappingSize,
    _gate: SpinLockGuard<'a, (), PreemptDisabled>,
    total: i128,
}

impl Frozen<'_> {
    fn total(&self) -> i128 {
        self.total
    }

    fn commit(&self, cpu: CpuId, delta: isize, total: i128) {
        let mut shard = self.accounting.shards.get_on_cpu(cpu).lock();
        if let Some(new) = shard.checked_add(delta) {
            *shard = new;
            return;
        }
        drop(shard);
        self.normalize(total);
    }

    fn normalize(&self, total: i128) {
        let total = isize::try_from(total).expect("mapped address space exceeds signed range");
        debug_assert!(total >= 0);
        // All ordinary writers remain frozen. No intermediate redistribution
        // can be mistaken for the total by a finite admission or exact query.
        for cpu in all_cpus() {
            *self.accounting.shards.get_on_cpu(cpu).lock() =
                if cpu == CpuId::bsp() { total } else { 0 };
        }
    }
}

impl Drop for Frozen<'_> {
    fn drop(&mut self) {
        // Drop runs before fields, so thaw always precedes releasing the gate,
        // including finite rejection and unwinding paths.
        self.accounting.frozen.store(false, Ordering::Release);
    }
}

#[cfg(ktest)]
impl MappingSize {
    /// Replaces only debt distribution, preserving the actual VMAR total.
    /// The caller holds the whole PT and excludes concurrent test operations.
    pub(super) fn seed_debt_for_test(&self, values: &[isize]) {
        use ostd::util::id_set::Id;

        let frozen = self.freeze();
        assert!(values.len() <= ostd::cpu::num_cpus());
        assert_eq!(
            frozen.total(),
            values.iter().map(|v| *v as i128).sum::<i128>()
        );
        for cpu in all_cpus() {
            *self.shards.get_on_cpu(cpu).lock() = values.get(cpu.as_usize()).copied().unwrap_or(0);
        }
    }
}
