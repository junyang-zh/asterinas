// SPDX-License-Identifier: MPL-2.0

//! Address space size and RSS counting/limiting.

use ostd::{
    cpu::{CpuId, PinCurrentCpu},
    task::DisabledPreemptGuard,
};

use super::Vmar;
use crate::{
    prelude::*,
    process::{
        Process, ResourceType,
        rlimit::{RLIM_INFINITY, RLimit64},
    },
};

impl Vmar {
    /// Adds the mapping size.
    ///
    /// Returns `Err` if the new size exceeds [`ResourceType::RLIMIT_AS`].
    pub(super) fn add_mapping_size(
        &self,
        preempt_guard: &DisabledPreemptGuard,
        add_size: usize,
    ) -> Result<()> {
        self.add_mapping_size_with_rlimit_as(preempt_guard, add_size, None)
    }

    pub(super) fn add_mapping_size_with_rlimit_as(
        &self,
        preempt_guard: &DisabledPreemptGuard,
        add_size: usize,
        rlimit_as: Option<&RLimit64>,
    ) -> Result<()> {
        let cur_cpu = preempt_guard.current_cpu();

        // Borrow the live object, so changes during mapping preparation or
        // page-table acquisition are observed at the usual admission point.
        let rlimit_as = match rlimit_as {
            Some(limit) => limit.get_cur(),
            None => get_rlimit_as(),
        };

        self.mapped_vm_size.add(cur_cpu, add_size, rlimit_as)
    }
}

/// The type representing categories of Resident Set Size (RSS).
///
/// See <https://github.com/torvalds/linux/blob/fac04efc5c793dccbd07e2d59af9f90b7fc0dca4/include/linux/mm_types_task.h#L26..L32>
#[repr(u32)]
#[derive(Debug, Clone, Copy, TryFromInt)]
pub(crate) enum RssType {
    File = 0,
    Anon = 1,
}

pub(super) const NUM_RSS_COUNTERS: usize = 2;

/// A helper struct to track resident set and address space size changes.
pub(crate) struct RsAsDelta<'a> {
    rs_as_delta: [isize; NUM_RSS_COUNTERS],
    as_delta: isize,
    operated_vmar: &'a Vmar,
}

impl<'a> RsAsDelta<'a> {
    pub(crate) fn new(operated_vmar: &'a Vmar) -> Self {
        Self {
            rs_as_delta: [0; NUM_RSS_COUNTERS],
            as_delta: 0,
            operated_vmar,
        }
    }

    pub(crate) fn add_rs(&mut self, rss_type: RssType, increment: isize) {
        self.rs_as_delta[rss_type as usize] += increment;
    }

    pub(crate) fn sub_as(&mut self, decrement: usize) {
        self.as_delta -= decrement as isize;
    }
}

impl Drop for RsAsDelta<'_> {
    fn drop(&mut self) {
        for i in 0..NUM_RSS_COUNTERS {
            let rss_type = RssType::try_from(i as u32).unwrap();
            let delta = self.rs_as_delta[rss_type as usize];
            self.operated_vmar.add_rss_counter(rss_type, delta);
        }
        // `current_racy` is OK because subtracting on any CPUs is OK.
        debug_assert!(self.as_delta <= 0);
        self.operated_vmar
            .mapped_vm_size
            .subtract(CpuId::current_racy(), self.as_delta);
    }
}

fn get_rlimit_as() -> u64 {
    let Some(process) = Process::current() else {
        // When building a `Process`, the kernel task needs to build
        // some `VmMapping`s, in which case this branch is reachable.
        return RLIM_INFINITY;
    };

    process
        .resource_limits()
        .get_rlimit(ResourceType::RLIMIT_AS)
        .get_cur()
}
