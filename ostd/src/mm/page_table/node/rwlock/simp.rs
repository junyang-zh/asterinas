// SPDX-License-Identifier: MPL-2.0

//! Simple atomic counter based readers-writer lock.

use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug)]
pub struct SimpRwLock {
    counter: AtomicU32,
}

impl SimpRwLock {
    const UNLOCKED: u32 = 0;
    const WRITE_LOCKED: u32 = 1;
    const READ_LOCKED: u32 = 2;

    pub const fn new() -> Self {
        Self {
            counter: AtomicU32::new(Self::UNLOCKED),
        }
    }

    pub fn lock_write(&self) {
        while self
            .counter
            .compare_exchange_weak(
                Self::UNLOCKED,
                Self::WRITE_LOCKED,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    pub fn unlock_write(&self) {
        self.counter.store(Self::UNLOCKED, Ordering::Release);
    }

    pub fn lock_read(&self) {
        loop {
            let counter = self.counter.load(Ordering::Acquire);
            if counter == Self::WRITE_LOCKED {
                core::hint::spin_loop();
                continue;
            }
            if self
                .counter
                .compare_exchange_weak(
                    counter,
                    counter + Self::READ_LOCKED,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }

    pub fn unlock_read(&self) {
        self.counter.fetch_sub(Self::READ_LOCKED, Ordering::Release);
    }
}
