// SPDX-License-Identifier: MPL-2.0

//! BRAVO visible readers over PFQ. Publication, bias revocation and the scan use
//! one sequentially consistent order: a reader either observes revocation and
//! withdraws, or its published slot is observed by the writer.

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

use super::pfq::PfqRwLock;
use crate::cpu::CpuId;

#[derive(Debug)]
pub struct BravoPfqRwLock {
    rbias: AtomicBool,
    revoke_pending: AtomicBool,
    inhibit_until: AtomicU64,
    underlying: PfqRwLock,
}

#[derive(Debug)]
pub struct BravoReadGuard {
    pos: Option<usize>,
}

const TABLE_SIZE: usize = 1021;
static VISIBLE_READERS: [AtomicPtr<BravoPfqRwLock>; TABLE_SIZE] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; TABLE_SIZE];

impl BravoPfqRwLock {
    pub const fn new() -> Self {
        Self {
            rbias: AtomicBool::new(false),
            revoke_pending: AtomicBool::new(false),
            inhibit_until: AtomicU64::new(0),
            underlying: PfqRwLock::new(),
        }
    }

    fn visible_read(&self) -> Option<BravoReadGuard> {
        if !self.rbias.load(Ordering::SeqCst) {
            return None;
        }
        let pos = self.hash();
        if VISIBLE_READERS[pos]
            .compare_exchange(
                core::ptr::null_mut(),
                self.as_ptr(),
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return None;
        }
        if self.rbias.load(Ordering::SeqCst) {
            Some(BravoReadGuard { pos: Some(pos) })
        } else {
            VISIBLE_READERS[pos].store(core::ptr::null_mut(), Ordering::Release);
            None
        }
    }

    fn enable_bias(&self) {
        // Called only with an underlying read lock, so no writer can revoke
        // concurrently. Signed differences handle timestamp wraparound.
        if self.rbias.load(Ordering::SeqCst) {
            return;
        }
        let deadline = self.inhibit_until.load(Ordering::Relaxed);
        if Self::deadline_reached(crate::arch::read_tsc(), deadline) {
            self.rbias.store(true, Ordering::SeqCst);
        }
    }

    pub fn lock_read(&self) -> BravoReadGuard {
        if let Some(guard) = self.visible_read() {
            return guard;
        }
        self.underlying.lock_read();
        self.enable_bias();
        BravoReadGuard { pos: None }
    }

    pub fn try_read(&self) -> Option<BravoReadGuard> {
        if let Some(guard) = self.visible_read() {
            return Some(guard);
        }
        if !self.underlying.try_read() {
            return None;
        }
        self.enable_bias();
        Some(BravoReadGuard { pos: None })
    }

    pub fn unlock_read(&self, guard: BravoReadGuard) {
        if let Some(pos) = guard.pos {
            debug_assert_eq!(VISIBLE_READERS[pos].load(Ordering::Relaxed), self.as_ptr());
            VISIBLE_READERS[pos].store(core::ptr::null_mut(), Ordering::Release);
        } else {
            self.underlying.unlock_read();
        }
    }

    pub fn lock_write(&self) {
        self.underlying.lock_write();
        if self.rbias.swap(false, Ordering::SeqCst) || self.revoke_pending.load(Ordering::Relaxed) {
            let start = crate::arch::read_tsc();
            for reader in &VISIBLE_READERS {
                while reader.load(Ordering::SeqCst) == self.as_ptr() {
                    core::hint::spin_loop();
                }
            }
            self.inhibit(start, crate::arch::read_tsc());
            self.revoke_pending.store(false, Ordering::Relaxed);
        }
    }

    pub fn try_write(&self) -> bool {
        if !self.underlying.try_write() {
            return false;
        }
        // Scan even if bias was already false: an earlier failed try-writer may
        // have revoked bias while visible readers were still draining.
        self.rbias.store(false, Ordering::SeqCst);
        let start = crate::arch::read_tsc();
        for reader in &VISIBLE_READERS {
            if reader.load(Ordering::SeqCst) == self.as_ptr() {
                self.revoke_pending.store(true, Ordering::Relaxed);
                self.inhibit(start, crate::arch::read_tsc());
                self.underlying.unlock_write();
                return false;
            }
        }
        self.inhibit(start, crate::arch::read_tsc());
        self.revoke_pending.store(false, Ordering::Relaxed);
        true
    }

    pub fn downgrade(&self) -> BravoReadGuard {
        self.underlying.downgrade();
        self.enable_bias();
        BravoReadGuard { pos: None }
    }

    pub fn unlock_write(&self) {
        self.underlying.unlock_write();
    }

    fn inhibit(&self, start: u64, end: u64) {
        let elapsed = end.wrapping_sub(start);
        let delay = elapsed.saturating_mul(9).min(i64::MAX as u64);
        // Replace the deadline; OR would retain stale high bits indefinitely.
        self.inhibit_until
            .store(end.wrapping_add(delay), Ordering::Relaxed);
    }

    fn deadline_reached(now: u64, deadline: u64) -> bool {
        now.wrapping_sub(deadline) as i64 >= 0
    }

    fn as_ptr(&self) -> *mut Self {
        self as *const Self as *mut Self
    }

    fn hash(&self) -> usize {
        let cpu = u32::from(CpuId::current_racy()) as usize;
        // Boxed node states can share a 64-KiB region. Keep their low address
        // bits, discarding only the lock's guaranteed alignment bits.
        let shift = core::mem::align_of::<Self>().trailing_zeros();
        let address = (self as *const Self as usize) >> shift;
        address.wrapping_add(cpu << 16) % TABLE_SIZE
    }
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    #[test]
    fn inhibition_replaces_deadline_and_handles_clock_wrap() {
        let lock = BravoPfqRwLock::new();
        lock.inhibit(100, 200);
        assert_eq!(lock.inhibit_until.load(Ordering::Relaxed), 1100);
        lock.inhibit(300, 301);
        assert_eq!(lock.inhibit_until.load(Ordering::Relaxed), 310);
        assert!(!BravoPfqRwLock::deadline_reached(u64::MAX - 4, 5));
        assert!(BravoPfqRwLock::deadline_reached(6, u64::MAX - 4));
        lock.inhibit(u64::MAX - 2, 2);
        assert_eq!(lock.inhibit_until.load(Ordering::Relaxed), 47);
    }
}
