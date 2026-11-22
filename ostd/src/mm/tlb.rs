// SPDX-License-Identifier: MPL-2.0

//! TLB flush operations.

#[cfg(feature = "lazy_tlb_flush_on_unmap")]
pub(crate) mod latr;

use alloc::vec::Vec;
use core::{mem::MaybeUninit, ops::Range, sync::atomic::Ordering};

use super::{
    PAGE_SIZE, Vaddr,
    frame::{Frame, meta::AnyFrameMeta},
};
use crate::{
    const_assert,
    cpu::{AtomicCpuSet, PinCurrentCpu},
    smp::{IpiSender, PendingIpis},
    sync::RcuDrop,
};

/// A TLB flusher that is aware of which CPUs are needed to be flushed.
///
/// The flusher needs to stick to the current CPU.
pub struct TlbFlusher<'a, G: PinCurrentCpu> {
    target_cpus: &'a AtomicCpuSet,
    pending_ipis: PendingIpis,
    ops_stack: OpsStack,
    ipi_sender: Option<&'static IpiSender>,
    _pin_current: G,
    #[cfg(feature = "lazy_tlb_flush_on_unmap")]
    has_lazy: bool,
}

impl<'a, G: PinCurrentCpu> TlbFlusher<'a, G> {
    /// Creates a new TLB flusher with the specified CPUs to be flushed.
    ///
    /// The target CPUs should be a reference to an [`AtomicCpuSet`] that will
    /// be loaded upon [`Self::dispatch_tlb_flush`].
    ///
    /// The flusher needs to stick to the current CPU. So please provide a
    /// guard that implements [`PinCurrentCpu`].
    pub fn new(target_cpus: &'a AtomicCpuSet, pin_current_guard: G) -> Self {
        Self {
            target_cpus,
            pending_ipis: PendingIpis::new_empty(),
            ops_stack: OpsStack::new(),
            ipi_sender: crate::smp::IPI_SENDER.get(),
            _pin_current: pin_current_guard,
            #[cfg(feature = "lazy_tlb_flush_on_unmap")]
            has_lazy: false,
        }
    }

    /// Issues a pending TLB flush request.
    ///
    /// This function does not guarantee to flush the TLB entries on either
    /// this CPU or remote CPUs. The flush requests are only performed when
    /// [`Self::dispatch_tlb_flush`] is called.
    pub fn issue_tlb_flush(&mut self, op: TlbFlushOp) {
        self.ops_stack.push(op, None);
    }

    /// Issues a TLB flush request that must happen before dropping the page.
    ///
    /// If we need to remove a mapped page from the page table, we can only
    /// recycle the page after all the relevant TLB entries in all CPUs are
    /// flushed. Otherwise if the page is recycled for other purposes, the user
    /// space program can still access the page through the TLB entries. This
    /// method is designed to be used in such cases.
    ///
    /// Furthermore, the frames will be dropped after the RCU grace period to
    /// ensure that no RCU references are held to the frames.
    pub fn issue_tlb_flush_with(
        &mut self,
        op: TlbFlushOp,
        drop_after_flush: RcuDrop<Frame<dyn AnyFrameMeta>>,
    ) {
        self.ops_stack.push(op, Some(drop_after_flush));
    }

    /// Retains an unmapped frame until lazy remote invalidation AND an RCU
    /// grace period complete. Permission revocations must use synchronous APIs.
    #[cfg(feature = "lazy_tlb_flush_on_unmap")]
    pub fn latr_with(&mut self, op: TlbFlushOp, frame: RcuDrop<Frame<dyn AnyFrameMeta>>) {
        let cpus = self.target_cpus.load(Ordering::Release);
        if let Err(frame) = latr::add(&cpus, op.clone(), frame) {
            self.issue_tlb_flush_with(op, frame);
        } else {
            self.has_lazy = true;
        }
    }

    /// Transfers eligible pure-unmap requests to bounded background ownership.
    /// Ordinary requests, including reserve overflow, still complete here.
    /// The covering VM cursor must publish its generation before unlocking.
    #[cfg(feature = "lazy_tlb_flush_on_unmap")]
    pub(crate) fn defer_unmap_flush(&mut self) -> bool {
        self.dispatch_tlb_flush();
        let deferred = core::mem::replace(&mut self.has_lazy, false);
        self.sync_tlb_flush();
        deferred
    }

    /// Completes lazy requests from all origins published before this barrier.
    /// Callbacks acknowledge only after architectural invalidation completes.
    #[cfg(feature = "lazy_tlb_flush_on_unmap")]
    pub(crate) fn sync_all_deferred_unmaps(&mut self) {
        let mut targets = crate::cpu::CpuSet::new_full();
        targets.remove(self._pin_current.current_cpu());
        let pending = self
            .ipi_sender
            .map(|sender| sender.inter_processor_call(&targets, latr::do_flush));
        latr::do_flush();
        if let Some(pending) = pending {
            pending.wait();
        }
    }

    /// Dispatches all the pending TLB flush requests.
    ///
    /// All previous pending requests issued by [`Self::issue_tlb_flush`] or
    /// [`Self::issue_tlb_flush_with`] starts to be processed after this
    /// function. But it may not be synchronous. Upon the return of this
    /// function, the TLB entries may not be coherent.
    pub fn dispatch_tlb_flush(&mut self) {
        #[cfg(feature = "lazy_tlb_flush_on_unmap")]
        if self.has_lazy {
            latr::flush_local();
        }
        if self.ops_stack.is_empty() {
            return;
        }

        let irq_guard = crate::irq::disable_local();

        // `Release` to make sure our modification on the PT is visible to CPUs
        // that are going to activate the PT.
        let mut target_cpus = self.target_cpus.load(Ordering::Release);

        let cur_cpu = irq_guard.current_cpu();
        let mut need_flush_on_self = false;

        if target_cpus.contains(cur_cpu) {
            target_cpus.remove(cur_cpu);
            need_flush_on_self = true;
        }

        if let Some(ipi_sender) = self.ipi_sender {
            let pending_ipis = ipi_sender.send_tlb_flush(&target_cpus, &self.ops_stack);
            self.pending_ipis.extend(&pending_ipis);
        }

        // Flush ourselves after sending all IPIs to save some time.
        if need_flush_on_self {
            self.ops_stack.flush_all();
        } else {
            self.ops_stack.clear_without_flush();
        }
    }

    /// A hint for switching away from the user root during a shared discard.
    /// Dispatch still snapshots the real targets with release ordering.
    #[cfg(all(target_arch = "x86_64", any(ktest, feature = "idle_shootdown_hint")))]
    pub(crate) fn has_shared_discard_work(&self) -> bool {
        !self.ops_stack.is_empty()
            && self
                .target_cpus
                .has_other_than(self._pin_current.current_cpu())
    }

    /// Dispatches queued invalidations and waits before retiring their frames.
    /// The caller's retained references cover every target until its callback
    /// completes, so the remote queues only need the invalidation operations.
    pub fn dispatch_and_wait(&mut self) {
        let frames =
            core::mem::ManuallyDrop::new(core::mem::take(&mut self.ops_stack.frame_keeper));
        self.dispatch_tlb_flush();
        self.sync_tlb_flush();

        // An unwind before acknowledgement must leave these references held.
        let frames = core::mem::ManuallyDrop::into_inner(frames);
        if !frames.is_empty() {
            drop(RcuDrop::new(frames));
        }
    }

    /// Waits for all the previous TLB flush requests to be completed.
    ///
    /// After this function, all TLB entries corresponding to previous
    /// dispatched TLB flush requests are guaranteed to be coherent.
    ///
    /// The TLB flush requests are issued with [`Self::issue_tlb_flush`] and
    /// dispatched with [`Self::dispatch_tlb_flush`]. This method will not
    /// dispatch any issued requests so it will not guarantee TLB coherence
    /// of requests that are not dispatched.
    ///
    /// # Panics
    ///
    /// This method panics if the IRQs are disabled. Since the remote flush are
    /// processed in IRQs, two CPUs may deadlock if they are waiting for each
    /// other's TLB coherence.
    pub fn sync_tlb_flush(&mut self) {
        #[cfg(feature = "lazy_tlb_flush_on_unmap")]
        if self.has_lazy {
            // Preserve the public synchronisation contract, including COW,
            // MAP_FIXED replacement and page-cache invalidation callers.
            latr::flush_local();
            if let Some(sender) = self.ipi_sender {
                let mut targets = latr::pending_cpus();
                targets.remove(self._pin_current.current_cpu());
                self.pending_ipis
                    .extend(&sender.inter_processor_call(&targets, latr::do_flush));
            }
            self.has_lazy = false;
        }

        if self.ipi_sender.is_none() {
            // We performed some TLB flushes in the boot context. The AP's boot
            // process should take care of them.
            return;
        }

        self.pending_ipis.wait();
        self.pending_ipis = PendingIpis::new_empty();
    }
}

impl<G: PinCurrentCpu> Drop for TlbFlusher<'_, G> {
    fn drop(&mut self) {
        // This is to ensure that frames issued by `issue_tlb_flush_with` will
        // not be dropped without flushing.
        self.dispatch_tlb_flush();
    }
}

/// The operation to flush TLB entries.
///
/// The variants of this structure are:
///  - Flushing all TLB entries except for the global entries;
///  - Flushing the TLB entry associated with an address;
///  - Flushing the TLB entries for a specific range of virtual addresses;
///
/// This is a `struct` instead of an `enum` because if trivially representing
/// the three variants with an `enum`, it would be 24 bytes. To minimize the
/// memory footprint, we encode all three variants into an 8-byte integer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlbFlushOp(Vaddr);

// We require the address to be page-aligned, so the in-page offset part of the
// address can be used to store the length. A sanity check to ensure that we
// don't allow ranged flush operations with a too long length.
const_assert!(TlbFlushOp::FLUSH_RANGE_NPAGES_MASK | (PAGE_SIZE - 1) == PAGE_SIZE - 1);

impl TlbFlushOp {
    const FLUSH_ALL_VAL: Vaddr = Vaddr::MAX;
    const FLUSH_RANGE_NPAGES_MASK: Vaddr =
        (1 << (usize::BITS - FLUSH_ALL_PAGES_THRESHOLD.leading_zeros())) - 1;

    /// Performs the TLB flush operation on the current CPU.
    pub fn perform_on_current(&self) {
        use crate::arch::mm;

        match self.0 {
            Self::FLUSH_ALL_VAL => mm::tlb_flush_all_excluding_global(),
            addr => {
                let start = addr & !Self::FLUSH_RANGE_NPAGES_MASK;
                let num_pages = addr & Self::FLUSH_RANGE_NPAGES_MASK;

                debug_assert!((addr & (PAGE_SIZE - 1)) < FLUSH_ALL_PAGES_THRESHOLD);
                debug_assert!(num_pages != 0);

                if num_pages == 1 {
                    mm::tlb_flush_addr(start);
                } else {
                    mm::tlb_flush_addr_range(&(start..start + num_pages * PAGE_SIZE));
                }
            }
        }
    }

    /// Creates a new TLB flush operation that flushes all TLB entries except
    /// for the global entries.
    pub const fn for_all() -> Self {
        TlbFlushOp(Self::FLUSH_ALL_VAL)
    }

    /// Creates a new TLB flush operation that flushes the TLB entry associated
    /// with the provided virtual address.
    pub const fn for_single(addr: Vaddr) -> Self {
        TlbFlushOp(addr | 1)
    }

    /// Creates a new TLB flush operation that flushes the TLB entries for the
    /// specified virtual address range.
    ///
    /// If the range is too large, the resulting [`TlbFlushOp`] will flush all
    /// TLB entries instead.
    ///
    /// # Panics
    ///
    /// Panics if the range is not page-aligned or if the range is empty.
    pub const fn for_range(range: Range<Vaddr>) -> Self {
        assert!(
            range.start.is_multiple_of(PAGE_SIZE),
            "range start must be page-aligned"
        );
        assert!(
            range.end.is_multiple_of(PAGE_SIZE),
            "range end must be page-aligned"
        );
        assert!(range.start < range.end, "range must not be empty");
        let num_pages = (range.end - range.start) / PAGE_SIZE;
        if num_pages >= FLUSH_ALL_PAGES_THRESHOLD {
            return TlbFlushOp::for_all();
        }
        TlbFlushOp(range.start | (num_pages as Vaddr))
    }

    /// Returns the number of pages to flush.
    ///
    /// If it returns `u32::MAX`, it means to flush all the entries. Otherwise
    /// the return value should be less than [`FLUSH_ALL_PAGES_THRESHOLD`] and
    /// non-zero.
    fn num_pages(&self) -> u32 {
        if self.0 == Self::FLUSH_ALL_VAL {
            u32::MAX
        } else {
            debug_assert!((self.0 & (PAGE_SIZE - 1)) < FLUSH_ALL_PAGES_THRESHOLD);
            let num_pages = (self.0 & Self::FLUSH_RANGE_NPAGES_MASK) as u32;
            debug_assert!(num_pages != 0);
            num_pages
        }
    }
}

#[cfg(feature = "idle_shootdown_hint")]
crate::cpu_local_cell! {
    static REMOTE_FLUSH_SEEN: u8 = 0;
}

/// Returns whether this CPU recently serviced a queued remote invalidation.
/// Idle tasks use this hint to stop borrowing a busy address space. Losing a
/// concurrent hint only postpones the optional address-space switch.
#[cfg(feature = "idle_shootdown_hint")]
pub fn take_remote_flush_hint() -> bool {
    if REMOTE_FLUSH_SEEN.load() == 0 {
        return false;
    }
    REMOTE_FLUSH_SEEN.store(0);
    true
}

/// If the number of pending pages to flush exceeds this threshold, we flush all the
/// TLB entries instead of flushing them one by one.
const FLUSH_ALL_PAGES_THRESHOLD: usize = 32;

pub(crate) struct OpsStack {
    /// From 0 to `num_ops`, the array entry must be initialized.
    ops: [MaybeUninit<TlbFlushOp>; FLUSH_ALL_PAGES_THRESHOLD],
    num_ops: u32,
    /// If this is `u32::MAX`, we should flush all entries irrespective of the
    /// contents of `ops`. And in this case `num_ops` must be zero.
    ///
    /// Otherwise, it counts the number of pages to flush in `ops`.
    num_pages_to_flush: u32,
    /// Keeps all the to-be-dropped frames.
    ///
    /// The elements cannot be modified after being pushed. And they must be
    /// dropped after the RCU grace period and the TLB flushes.
    frame_keeper: Vec<Frame<dyn AnyFrameMeta>>,
}

impl OpsStack {
    pub(crate) const fn new() -> Self {
        Self {
            ops: [const { MaybeUninit::uninit() }; FLUSH_ALL_PAGES_THRESHOLD],
            num_ops: 0,
            num_pages_to_flush: 0,
            frame_keeper: Vec::new(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.num_ops == 0 && self.num_pages_to_flush == 0
    }

    fn need_flush_all(&self) -> bool {
        self.num_pages_to_flush == u32::MAX
    }

    fn push(&mut self, op: TlbFlushOp, drop_after_flush: Option<RcuDrop<Frame<dyn AnyFrameMeta>>>) {
        if let Some(frame) = drop_after_flush {
            self.frame_keeper.reserve(1);
            // SAFETY: By pushing into the `frame_keeper`, the frame will be
            // dropped after the RCU grace period.
            let (frame, panic_guard) = unsafe { RcuDrop::into_inner(frame) };
            self.frame_keeper.push(frame);
            panic_guard.forget();
        }

        if self.need_flush_all() {
            return;
        }
        let op_num_pages = op.num_pages();
        if op == TlbFlushOp::for_all()
            || self.num_pages_to_flush + op_num_pages >= FLUSH_ALL_PAGES_THRESHOLD as u32
        {
            self.num_pages_to_flush = u32::MAX;
            self.num_ops = 0;
            return;
        }

        self.ops[self.num_ops as usize].write(op);
        self.num_ops += 1;
        self.num_pages_to_flush += op_num_pages;
    }

    pub(crate) fn push_from(&mut self, other: &OpsStack) {
        self.frame_keeper.extend(other.frame_keeper.iter().cloned());

        if self.need_flush_all() {
            return;
        }
        if other.need_flush_all()
            || self.num_pages_to_flush + other.num_pages_to_flush
                >= FLUSH_ALL_PAGES_THRESHOLD as u32
        {
            self.num_pages_to_flush = u32::MAX;
            self.num_ops = 0;
            return;
        }

        for other_op in other.ops_iter() {
            self.ops[self.num_ops as usize].write(other_op.clone());
            self.num_ops += 1;
        }
        self.num_pages_to_flush += other.num_pages_to_flush;
    }

    pub(crate) fn flush_on_remote(&mut self) {
        debug_assert!(!self.is_empty());
        #[cfg(feature = "idle_shootdown_hint")]
        REMOTE_FLUSH_SEEN.store(1);
        self.flush_all();
    }

    fn flush_all(&mut self) {
        if self.need_flush_all() {
            crate::arch::mm::tlb_flush_all_excluding_global();
        } else {
            self.ops_iter().for_each(|op| {
                op.perform_on_current();
            });
        }

        self.clear_without_flush();
    }

    fn clear_without_flush(&mut self) {
        self.num_pages_to_flush = 0;
        self.num_ops = 0;
        if !self.frame_keeper.is_empty() {
            let _ = RcuDrop::new(core::mem::take(&mut self.frame_keeper));
        }
    }

    fn ops_iter(&self) -> impl Iterator<Item = &TlbFlushOp> {
        self.ops.iter().take(self.num_ops as usize).map(|op| {
            // SAFETY: From 0 to `num_ops`, the array entry must be initialized.
            unsafe { op.assume_init_ref() }
        })
    }
}

impl Drop for OpsStack {
    fn drop(&mut self) {
        if !self.frame_keeper.is_empty() {
            let _ = RcuDrop::new(core::mem::take(&mut self.frame_keeper));
        }
    }
}

#[cfg(ktest)]
mod owner_test {
    use super::*;
    use crate::{
        cpu::{AtomicCpuSet, CpuSet},
        mm::FrameAllocOptions,
        prelude::*,
        task::disable_preempt,
    };

    #[ktest]
    fn synchronous_dispatch_retains_frames_through_the_read_side_section() {
        let targets = AtomicCpuSet::new(CpuSet::new_full());
        let mut flusher = TlbFlusher::new(&targets, disable_preempt());
        let frame = FrameAllocOptions::new().alloc_frame().unwrap();
        // Exercise both single-address and full-flush batches.
        for pages in [1, FLUSH_ALL_PAGES_THRESHOLD] {
            let before = frame.reference_count();
            for i in 1..=pages {
                flusher.issue_tlb_flush_with(
                    TlbFlushOp::for_single(i * PAGE_SIZE),
                    RcuDrop::new(frame.clone().into()),
                );
            }
            flusher.dispatch_and_wait();
            assert!(flusher.ops_stack.is_empty());
            assert!(flusher.ops_stack.frame_keeper.is_empty());
            assert_eq!(frame.reference_count(), before + pages as u64);
        }
    }
}
