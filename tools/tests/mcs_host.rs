// SPDX-License-Identifier: MPL-2.0
// Run with: rustc --edition=2024 --test tools/tests/mcs_host.rs -o /tmp/mcs-test && /tmp/mcs-test
#[path = "../../ostd/src/mm/page_table/node/mcs.rs"]
mod mcs;

use std::{cell::UnsafeCell, sync::Arc, thread};
struct Shared {
    lock: mcs::LockBody,
    value: UnsafeCell<usize>,
}
// SAFETY: Accesses to value in these tests are exclusively protected by lock.
unsafe impl Sync for Shared {}

#[test]
fn contended_handoffs_preserve_exclusive_access() {
    let shared = Arc::new(Shared {
        lock: mcs::LockBody::new(),
        value: UnsafeCell::new(0),
    });
    let mut threads = Vec::new();
    for _ in 0..8 {
        let shared = shared.clone();
        threads.push(thread::spawn(move || {
            for _ in 0..20_000 {
                let node = Box::pin(mcs::Node::new());
                unsafe {
                    node.as_ref().lock(&shared.lock);
                    *shared.value.get() += 1;
                    node.as_ref().unlock(&shared.lock);
                }
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(unsafe { *shared.value.get() }, 160_000);
}

#[test]
fn try_lock_fails_without_enqueuing_and_recovers_after_unlock() {
    let lock = mcs::LockBody::new();
    let owner = Box::pin(mcs::Node::new());
    let contender = Box::pin(mcs::Node::new());
    unsafe {
        assert!(owner.as_ref().try_lock(&lock));
        assert!(!contender.as_ref().try_lock(&lock));
        owner.as_ref().unlock(&lock);
        assert!(contender.as_ref().try_lock(&lock));
        contender.as_ref().unlock(&lock);
        let next = Box::pin(mcs::Node::new());
        assert!(next.as_ref().try_lock(&lock));
        next.as_ref().unlock(&lock);
    }
}
