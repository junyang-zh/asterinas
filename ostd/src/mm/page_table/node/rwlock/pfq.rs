// SPDX-License-Identifier: MPL-2.0

//! Phase-fair reader admission with FIFO MCS-queued blocking writers.
//!
//! Readers arriving during a writer register for the next reader phase. The
//! following writer waits for those readers as well as already active readers.
//! Try-writers use a separate atomic reservation: a failed attempt never joins
//! the MCS queue, waits for readers, or waits for an MCS successor to link.

use alloc::boxed::Box;
use core::{
    cell::SyncUnsafeCell,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use super::super::mcs;

const READER: u64 = 4;
const PHASE: u64 = 1;
const WRITER: u64 = 2;
const COUNT: u64 = !(PHASE | WRITER);

#[derive(Debug)]
pub struct PfqRwLock {
    rin: AtomicU64,
    rout: AtomicU64,
    writer: AtomicBool,
    queue: mcs::LockBody,
    owner: SyncUnsafeCell<Option<Pin<Box<mcs::Node>>>>,
}

impl PfqRwLock {
    pub const fn new() -> Self {
        Self {
            rin: AtomicU64::new(0),
            rout: AtomicU64::new(0),
            writer: AtomicBool::new(false),
            queue: mcs::LockBody::new(),
            owner: SyncUnsafeCell::new(None),
        }
    }

    pub fn lock_read(&self) {
        let ticket = self.rin.fetch_add(READER, Ordering::Acquire);
        if ticket & WRITER != 0 {
            // A phase flip admits this reader even if the next writer has
            // already set WRITER: that writer must wait for our registered ticket.
            while self.rin.load(Ordering::Acquire) & (WRITER | PHASE) == ticket & (WRITER | PHASE) {
                core::hint::spin_loop();
            }
        }
    }

    pub fn try_read(&self) -> bool {
        let state = self.rin.load(Ordering::Relaxed);
        state & WRITER == 0
            && self
                .rin
                .compare_exchange(
                    state,
                    state.wrapping_add(READER),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
    }

    pub fn unlock_read(&self) {
        self.rout.fetch_add(READER, Ordering::Release);
    }

    pub fn lock_write(&self) {
        let node = Box::pin(mcs::Node::new());
        // SAFETY: The fresh pinned node remains alive until unlock_write.
        unsafe { node.as_ref().lock(&self.queue) };
        while self
            .writer
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: The writer reservation exclusively protects owner.
        unsafe { self.owner.get().write(Some(node)) };
        let readers = self.rin.fetch_or(WRITER, Ordering::AcqRel) & COUNT;
        while self.rout.load(Ordering::Acquire) & COUNT != readers {
            core::hint::spin_loop();
        }
    }

    pub fn try_write(&self) -> bool {
        if self
            .writer
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        let state = self.rin.load(Ordering::Acquire);
        if state & COUNT != self.rout.load(Ordering::Acquire) & COUNT
            || self
                .rin
                .compare_exchange(state, state | WRITER, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            self.writer.store(false, Ordering::Release);
            return false;
        }
        // No queue node belongs to a try-writer, so rollback cannot wait on the queue.
        true
    }

    /// Registers the writer itself in the next reader phase before publishing
    /// that phase, so ownership never has an unprotected gap.
    pub fn downgrade(&self) {
        self.rin.fetch_add(READER, Ordering::Relaxed);
        self.unlock_write();
    }

    pub fn unlock_write(&self) {
        // SAFETY: The writer reservation exclusively protects owner.
        let owner = unsafe { self.owner.get().replace(None) };
        // Release publishes writes and admits all readers registered this phase.
        self.rin.fetch_xor(WRITER | PHASE, Ordering::Release);
        self.writer.store(false, Ordering::Release);
        if let Some(node) = owner {
            // SAFETY: This pinned node acquired queue in lock_write.
            unsafe { node.as_ref().unlock(&self.queue) };
        }
    }
}
