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

    // Run the actual-module host harness with --test-threads=1: its visible
    // table is global. An external process timeout also bounds a stuck join.
    use std::{
        sync::{Arc, atomic::AtomicUsize, mpsc},
        thread,
        time::{Duration, Instant},
    };

    const WAIT: Duration = Duration::from_secs(5);

    struct Read<'a> {
        lock: &'a BravoPfqRwLock,
        guard: Option<BravoReadGuard>,
    }

    impl<'a> Read<'a> {
        fn acquire(lock: &'a BravoPfqRwLock, try_read: bool) -> Self {
            let guard = if try_read {
                lock.try_read().expect("uncontended read must succeed")
            } else {
                lock.lock_read()
            };
            Self { lock, guard: Some(guard) }
        }

        fn pos(&self) -> Option<usize> {
            self.guard.as_ref().unwrap().pos
        }
    }

    impl Drop for Read<'_> {
        fn drop(&mut self) {
            if let Some(guard) = self.guard.take() {
                self.lock.unlock_read(guard);
            }
        }
    }

    fn collision_fallback_excludes_writers(try_read: bool) {
        let lock = Arc::new(BravoPfqRwLock::new());
        let value = Arc::new(AtomicUsize::new(0));
        // All three acquisitions run on this thread's fixed CPU shim identity.
        let initial = Read::acquire(&lock, false);
        assert_eq!(initial.pos(), None);
        let visible = Read::acquire(&lock, false);
        assert_eq!(visible.pos(), Some(lock.hash()));
        let fallback = Read::acquire(&lock, try_read);
        assert_eq!(fallback.pos(), None, "occupied slot must use PFQ");
        assert!(lock.rbias.load(Ordering::SeqCst));
        assert_eq!(VISIBLE_READERS[lock.hash()].load(Ordering::SeqCst), lock.as_ptr());
        drop(initial);
        drop(visible);
        // Only the forced fallback remains; visible ownership cannot mask a
        // missing underlying read registration in the assertions below.
        assert!(VISIBLE_READERS[lock.hash()].load(Ordering::SeqCst).is_null());

        let (attempt_tx, attempt_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_lock = lock.clone();
        let worker_value = value.clone();
        let writer = thread::spawn(move || {
            let acquired = worker_lock.try_write();
            if acquired {
                worker_lock.unlock_write();
            }
            let _ = attempt_tx.send(acquired);
            worker_lock.lock_write();
            worker_value.store(73, Ordering::SeqCst);
            worker_lock.unlock_write();
            let _ = done_tx.send(());
        });

        // Save all outcomes until the retained guard is released and the
        // worker joined, including timeout/error paths. No assertion can leave
        // the writer waiting on a guard owned by a panicking test thread.
        let attempted = attempt_rx.recv_timeout(WAIT);
        let deadline = Instant::now() + WAIT;
        let mut writer_registered = false;
        while Instant::now() < deadline {
            // With no other admitting reader, failure is evidence that the
            // real PFQ writer has set WRITER (or raced this probe to set it).
            // A notification sent before lock_write would not prove this.
            if !lock.underlying.try_read() {
                writer_registered = true;
                break;
            }
            lock.underlying.unlock_read();
            thread::yield_now();
        }
        let value_while_held = value.load(Ordering::SeqCst);
        let completion_while_held = done_rx.try_recv();
        drop(fallback);
        let completed = done_rx.recv_timeout(WAIT);
        // A lock bug may prevent join from returning even after release; the
        // documented external timeout is mandatory for this host harness.
        let joined = writer.join();
        assert_eq!(attempted.unwrap(), false, "try-writer passed fallback reader");
        assert!(writer_registered, "blocking writer never registered with PFQ");
        assert_eq!(value_while_held, 0, "blocking writer passed fallback reader");
        assert!(matches!(completion_while_held, Err(mpsc::TryRecvError::Empty)));
        assert!(completed.is_ok(), "writer did not complete after reader release");
        assert!(joined.is_ok(), "writer panicked");
        let after = Read::acquire(&lock, false);
        assert_eq!(value.load(Ordering::Relaxed), 73);
        drop(after);
        assert!(lock.try_write(), "fallback or queued writer leaked ownership");
        lock.unlock_write();
    }

    #[test]
    fn blocking_collision_fallback_excludes_try_and_queued_writers() {
        collision_fallback_excludes_writers(false);
    }

    #[test]
    fn try_collision_fallback_excludes_try_and_queued_writers() {
        collision_fallback_excludes_writers(true);
    }

    #[test]
    fn nearby_allocated_locks_keep_distinct_visible_ownership() {
        // Real, aligned objects with ordinary Rust lifetimes, in one bounded
        // allocation. No allocator adjacency or fabricated pointer is needed.
        #[repr(align(65536))]
        struct Pair([BravoPfqRwLock; 2]);
        let pair = Box::new(Pair([BravoPfqRwLock::new(), BravoPfqRwLock::new()]));
        let first = &pair.0[0];
        let second = &pair.0[1];
        let cpu = u32::from(CpuId::current_racy()) as usize;
        let first_address = first as *const BravoPfqRwLock as usize;
        let second_address = second as *const BravoPfqRwLock as usize;
        assert_eq!(first_address % core::mem::align_of::<BravoPfqRwLock>(), 0);
        assert_eq!(second_address % core::mem::align_of::<BravoPfqRwLock>(), 0);
        // Check the old CPU-shifted bucket precondition on actual addresses.
        assert_eq!(first_address.wrapping_add(cpu) >> 16,
                   second_address.wrapping_add(cpu) >> 16);
        assert_ne!(first.hash(), second.hash());
        drop(Read::acquire(first, false));
        drop(Read::acquire(second, false));
        for try_read in [false, true] {
            let first_read = Read::acquire(first, try_read);
            let second_read = Read::acquire(second, try_read);
            assert_eq!(first_read.pos(), Some(first.hash()));
            assert_eq!(second_read.pos(), Some(second.hash()));
            assert_eq!(VISIBLE_READERS[first.hash()].load(Ordering::SeqCst), first.as_ptr());
            assert_eq!(VISIBLE_READERS[second.hash()].load(Ordering::SeqCst), second.as_ptr());
            // Reusing the occupied slot falls back without replacing its owner.
            let nested = Read::acquire(first, try_read);
            assert_eq!(nested.pos(), None);
            assert_eq!(VISIBLE_READERS[first.hash()].load(Ordering::SeqCst), first.as_ptr());
            drop(nested);
            drop(second_read);
            assert!(VISIBLE_READERS[second.hash()].load(Ordering::SeqCst).is_null());
            assert_eq!(VISIBLE_READERS[first.hash()].load(Ordering::SeqCst), first.as_ptr());
            drop(first_read);
            assert!(VISIBLE_READERS[first.hash()].load(Ordering::SeqCst).is_null());
        }
    }
}
