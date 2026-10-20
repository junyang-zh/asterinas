// SPDX-License-Identifier: MPL-2.0
// Tests compile the actual kernel lock modules, with only CPU/TSC host shims.
#![feature(sync_unsafe_cell)]
extern crate alloc;
#[path = "../../ostd/src/mm/page_table/node/mcs.rs"]
mod mcs;
#[path = "../../ostd/src/mm/page_table/node/rwlock/mod.rs"]
mod rwlock;
mod cpu {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! { static ID: usize = NEXT.fetch_add(1, Ordering::Relaxed); }
    pub struct CpuId(usize);
    impl From<CpuId> for u32 {
        fn from(id: CpuId) -> Self {
            id.0 as u32
        }
    }
    impl CpuId {
        pub fn current_racy() -> Self {
            Self(ID.with(|id| *id))
        }
        pub fn as_usize(&self) -> usize {
            self.0
        }
    }
}
mod arch {
    pub fn read_tsc() -> u64 {
        // SAFETY: x86_64 host supports RDTSC; value used only for bias hysteresis.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
}
use std::{
    cell::UnsafeCell,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use rwlock::bravo::BravoPfqRwLock;
struct Shared {
    lock: BravoPfqRwLock,
    value: UnsafeCell<(usize, usize)>,
    readers: AtomicUsize,
    writers: AtomicUsize,
}
// SAFETY: Accesses to value are protected by the actual lock under test.
unsafe impl Sync for Shared {}

#[test]
fn concurrent_readers_writers_and_try_rollback_preserve_exclusion() {
    let s = Arc::new(Shared {
        lock: BravoPfqRwLock::new(),
        value: UnsafeCell::new((0, 0)),
        readers: AtomicUsize::new(0),
        writers: AtomicUsize::new(0),
    });
    let barrier = Arc::new(Barrier::new(8));
    let mut joins = Vec::new();
    for id in 0..8 {
        let s = s.clone();
        let barrier = barrier.clone();
        joins.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..10_000 {
                if id % 2 == 0 {
                    let r = if i % 2 == 0 {
                        s.lock.lock_read()
                    } else {
                        loop {
                            if let Some(r) = s.lock.try_read() {
                                break r;
                            }
                            thread::yield_now();
                        }
                    };
                    s.readers.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(s.writers.load(Ordering::SeqCst), 0);
                    let pair = unsafe { *s.value.get() };
                    assert_eq!(pair.0, pair.1);
                    s.readers.fetch_sub(1, Ordering::SeqCst);
                    s.lock.unlock_read(r);
                } else {
                    if i % 2 == 0 {
                        s.lock.lock_write();
                    } else {
                        while !s.lock.try_write() {
                            thread::yield_now();
                        }
                    }
                    assert_eq!(s.writers.fetch_add(1, Ordering::SeqCst), 0);
                    assert_eq!(s.readers.load(Ordering::SeqCst), 0);
                    unsafe {
                        (*s.value.get()).0 += 1;
                        (*s.value.get()).1 += 1;
                    }
                    assert_eq!(s.writers.fetch_sub(1, Ordering::SeqCst), 1);
                    s.lock.unlock_write();
                }
            }
        }));
    }
    for j in joins {
        j.join().unwrap();
    }
    assert_eq!(unsafe { *s.value.get() }, (40_000, 40_000));
}

#[test]
fn try_conflicts_return_before_owner_releases_and_can_reacquire() {
    let lock = BravoPfqRwLock::new();
    let first = lock.lock_read();
    let visible = lock.lock_read();
    lock.unlock_read(first); // Only a visible reader remains.
    assert!(!lock.try_write());
    assert!(!lock.try_write()); // Revoked bias must not hide the visible reader.
    lock.unlock_read(visible);
    assert!(lock.try_write());
    assert!(lock.try_read().is_none());
    assert!(!lock.try_write());
    lock.unlock_write();
    let r = lock.try_read().unwrap();
    assert!(!lock.try_write());
    lock.unlock_read(r);
    assert!(lock.try_write());
    lock.unlock_write();
}

#[test]
fn failed_try_revocation_is_respected_by_blocking_writer() {
    let lock = Arc::new(BravoPfqRwLock::new());
    let first = lock.lock_read();
    let visible = lock.lock_read();
    lock.unlock_read(first);
    assert!(!lock.try_write());
    let entered = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Barrier::new(2));
    let j = {
        let lock = lock.clone();
        let entered = entered.clone();
        let started = started.clone();
        thread::spawn(move || {
            started.wait();
            lock.lock_write();
            entered.store(1, Ordering::SeqCst);
            lock.unlock_write();
        })
    };
    started.wait();
    for _ in 0..10_000 {
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        thread::yield_now();
    }
    lock.unlock_read(visible);
    j.join().unwrap();
    assert_eq!(entered.load(Ordering::SeqCst), 1);
}

#[test]
fn downgrade_retains_reader_ownership() {
    let lock = BravoPfqRwLock::new();
    assert!(lock.try_write());
    let r = lock.downgrade();
    assert!(!lock.try_write());
    let r2 = lock.try_read().unwrap();
    lock.unlock_read(r2);
    lock.unlock_read(r);
    assert!(lock.try_write());
    lock.unlock_write();
}

#[test]
fn independent_readers_can_hold_the_lock_simultaneously() {
    let lock = Arc::new(BravoPfqRwLock::new());
    let barrier = Arc::new(Barrier::new(8));
    let mut joins = Vec::new();
    for _ in 0..8 {
        let lock = lock.clone();
        let barrier = barrier.clone();
        joins.push(thread::spawn(move || {
            let read = lock.lock_read();
            barrier.wait(); // A mutex substituted for a rwlock deadlocks here.
            lock.unlock_read(read);
        }));
    }
    for join in joins {
        join.join().unwrap();
    }
}
