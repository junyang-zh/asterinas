// SPDX-License-Identifier: MPL-2.0
// FIXME: The resource limits should be respected by the corresponding subsystems of the kernel.

use core::{
    array,
    sync::atomic::{AtomicU64, Ordering},
};

use super::process_vm::INIT_STACK_SIZE;
use crate::{
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet},
    security::lsm::hooks as lsm_hooks,
};

// Constants for the boot-time rlimit defaults
// See https://github.com/torvalds/linux/blob/fac04efc5c793dccbd07e2d59af9f90b7fc0dca4/include/asm-generic/resource.h#L11
pub(crate) const RLIM_INFINITY: u64 = u64::MAX;
const INIT_RLIMIT_NPROC: u64 = 0;
const INIT_RLIMIT_NICE: u64 = 0;
const INIT_RLIMIT_SIGPENDING: u64 = 0;
const INIT_RLIMIT_RTPRIO: u64 = 0;
// https://github.com/torvalds/linux/blob/fac04efc5c793dccbd07e2d59af9f90b7fc0dca4/include/uapi/linux/fs.h#L37
const INIT_RLIMIT_NOFILE_CUR: u64 = 1024;
const INIT_RLIMIT_NOFILE_MAX: u64 = 4096;
// https://github.com/torvalds/linux/blob/fac04efc5c793dccbd07e2d59af9f90b7fc0dca4/include/uapi/linux/resource.h#L79
const INIT_RLIMIT_MEMLOCK: u64 = 8 * 1024 * 1024;
// https://github.com/torvalds/linux/blob/fac04efc5c793dccbd07e2d59af9f90b7fc0dca4/include/uapi/linux/mqueue.h#L26
const INIT_RLIMIT_MSGQUEUE: u64 = 819200;
// https://github.com/torvalds/linux/blob/fac04efc5c793dccbd07e2d59af9f90b7fc0dca4/fs/file.c#L90
pub(crate) const SYSCTL_NR_OPEN: u64 = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct ResourceLimits {
    rlimits: [RLimit64; RLIMIT_COUNT],
}

impl ResourceLimits {
    /// Returns a reference to a specific resource limit.
    pub(crate) fn get_rlimit(&self, resource: ResourceType) -> &RLimit64 {
        &self.rlimits[resource as usize]
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        let mut rlimits: [RLimit64; RLIMIT_COUNT] = array::from_fn(|_| RLimit64::default());

        // Sets the resource limits with predefined values
        rlimits[ResourceType::RLIMIT_CPU as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::RLIMIT_FSIZE as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::RLIMIT_DATA as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::RLIMIT_STACK as usize] =
            RLimit64::new(INIT_STACK_SIZE as u64, RLIM_INFINITY);
        rlimits[ResourceType::RLIMIT_CORE as usize] = RLimit64::new(0, RLIM_INFINITY);
        rlimits[ResourceType::RLIMIT_RSS as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::RLIMIT_NPROC as usize] =
            RLimit64::new(INIT_RLIMIT_NPROC, INIT_RLIMIT_NPROC);
        rlimits[ResourceType::RLIMIT_NOFILE as usize] =
            RLimit64::new(INIT_RLIMIT_NOFILE_CUR, INIT_RLIMIT_NOFILE_MAX);
        rlimits[ResourceType::RLIMIT_MEMLOCK as usize] =
            RLimit64::new(INIT_RLIMIT_MEMLOCK, INIT_RLIMIT_MEMLOCK);
        rlimits[ResourceType::RLIMIT_AS as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::RLIMIT_LOCKS as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::RLIMIT_SIGPENDING as usize] =
            RLimit64::new(INIT_RLIMIT_SIGPENDING, INIT_RLIMIT_SIGPENDING);
        rlimits[ResourceType::RLIMIT_MSGQUEUE as usize] =
            RLimit64::new(INIT_RLIMIT_MSGQUEUE, INIT_RLIMIT_MSGQUEUE);
        rlimits[ResourceType::RLIMIT_NICE as usize] =
            RLimit64::new(INIT_RLIMIT_NICE, INIT_RLIMIT_NICE);
        rlimits[ResourceType::RLIMIT_RTPRIO as usize] =
            RLimit64::new(INIT_RLIMIT_RTPRIO, INIT_RLIMIT_RTPRIO);
        rlimits[ResourceType::RLIMIT_RTTIME as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);

        ResourceLimits { rlimits }
    }
}

#[expect(non_camel_case_types)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub(crate) enum ResourceType {
    RLIMIT_CPU = 0,
    RLIMIT_FSIZE = 1,
    RLIMIT_DATA = 2,
    RLIMIT_STACK = 3,
    RLIMIT_CORE = 4,
    RLIMIT_RSS = 5,
    RLIMIT_NPROC = 6,
    RLIMIT_NOFILE = 7,
    RLIMIT_MEMLOCK = 8,
    RLIMIT_AS = 9,
    RLIMIT_LOCKS = 10,
    RLIMIT_SIGPENDING = 11,
    RLIMIT_MSGQUEUE = 12,
    RLIMIT_NICE = 13,
    RLIMIT_RTPRIO = 14,
    RLIMIT_RTTIME = 15,
}

const RLIMIT_COUNT: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(crate) struct RawRLimit64 {
    pub cur: u64,
    pub max: u64,
}

#[derive(Debug)]
pub(crate) struct RLimit64 {
    cur: AtomicU64,
    max: AtomicU64,
    lock: SpinLock<()>,
}

impl RLimit64 {
    #[track_caller]
    pub(self) const fn new(cur: u64, max: u64) -> Self {
        assert!(cur <= max, "the current rlimit exceeds the max rlimit");
        Self {
            cur: AtomicU64::new(cur),
            max: AtomicU64::new(max),
            lock: SpinLock::new(()),
        }
    }

    /// Returns the current rlimit without synchronization.
    pub(crate) fn get_cur(&self) -> u64 {
        self.cur.load(Ordering::Relaxed)
    }

    /// Returns the max rlimit without synchronization.
    fn get_max(&self) -> u64 {
        self.max.load(Ordering::Relaxed)
    }

    /// Gets the rlimit with synchronization.
    ///
    /// Only called when handling the `getrlimit` or `prlimit` syscall.
    pub(crate) fn get_raw_rlimit(&self) -> RawRLimit64 {
        let _guard = self.lock.lock();
        RawRLimit64 {
            cur: self.cur.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
        }
    }

    /// Sets the rlimit with synchronization and returns the old value.
    ///
    /// Only called when handling the `setrlimit` or `prlimit` syscall.
    pub(crate) fn set_raw_rlimit(&self, new: RawRLimit64, ctx: &Context) -> Result<RawRLimit64> {
        if new.cur > new.max {
            return_errno_with_message!(Errno::EINVAL, "the current rlimit exceeds the max rlimit");
        }
        let _guard = self.lock.lock();
        if new.max > self.get_max() {
            let init_user_ns = UserNamespace::get_init_singleton();
            lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
                init_user_ns.as_ref(),
                ctx.posix_thread,
                CapSet::SYS_RESOURCE,
            ))?;
        }
        let old = RawRLimit64 {
            cur: self.cur.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
        };
        self.set_raw_rlimit_unchecked(new);
        Ok(old)
    }

    /// Sets the rlimit _without_ synchronization and permission check.
    ///
    /// Only called during init process creation.
    #[track_caller]
    pub(self) fn set_raw_rlimit_unchecked(&self, new: RawRLimit64) {
        assert!(
            new.cur <= new.max,
            "the current rlimit exceeds the max rlimit"
        );
        self.cur.store(new.cur, Ordering::Relaxed);
        self.max.store(new.max, Ordering::Relaxed);
    }
}

impl Default for RLimit64 {
    fn default() -> Self {
        Self {
            cur: AtomicU64::new(RLIM_INFINITY),
            max: AtomicU64::new(RLIM_INFINITY),
            lock: SpinLock::new(()),
        }
    }
}

impl Clone for RLimit64 {
    fn clone(&self) -> Self {
        let raw_limit = self.get_raw_rlimit();
        Self {
            cur: AtomicU64::new(raw_limit.cur),
            max: AtomicU64::new(raw_limit.max),
            lock: SpinLock::new(()),
        }
    }
}

/// Creates resource limits for the init process.
///
/// This function should be used when creating the init process to ensure it has
/// appropriate resource limits.
pub(super) fn new_resource_limits_for_init() -> ResourceLimits {
    let resource_limits = ResourceLimits::default();
    // FIXME: The value should be calculated based on the system capacity. For now, we set a
    // fixed value. In Linux, this value is determined by the kernel based on the available memory
    // and other factors.
    // Reference: <https://elixir.bootlin.com/linux/v6.16.9/source/kernel/fork.c#L761>
    let max_threads: u64 = 100000;
    let raw_rlimit = RawRLimit64 {
        cur: max_threads / 2,
        max: max_threads / 2,
    };
    resource_limits
        .get_rlimit(ResourceType::RLIMIT_NPROC)
        .set_raw_rlimit_unchecked(raw_rlimit);
    resource_limits
        .get_rlimit(ResourceType::RLIMIT_SIGPENDING)
        .set_raw_rlimit_unchecked(raw_rlimit);
    resource_limits
}

#[cfg(ktest)]
mod rlimit_borrow_test {
    use core::num::NonZeroUsize;

    use ostd::prelude::ktest;

    use super::*;
    use crate::{
        fs::pseudofs::SockFs,
        process::{Process, ProcessVm},
        vm::{
            page_cache::VmoOptions,
            perms::VmPerms,
            vmar::{OffsetType, Vmar, VmarHandle},
        },
    };

    const ADDR: usize = 0x200_000;

    fn new_vmar() -> VmarHandle {
        crate::time::clocks::init_for_ktest();
        crate::util::random::init();
        assert!(Process::current().is_none());
        VmarHandle::new(ProcessVm::new(SockFs::new_path())).unwrap()
    }

    fn set_cur(limit: &RLimit64, cur: usize) {
        limit.set_raw_rlimit_unchecked(RawRLimit64 {
            cur: cur as u64,
            max: RLIM_INFINITY,
        });
    }

    fn assert_present(vmar: &Vmar, addr: usize, size: usize) {
        let mut count = 0;
        vmar.for_each_mapping(addr..addr + size, true, |_| count += 1)
            .unwrap();
        assert!(count > 0);
    }

    fn assert_absent(vmar: &Vmar, addr: usize, size: usize) {
        let mut count = 0;
        vmar.for_each_mapping(addr..addr + size, false, |_| count += 1)
            .unwrap();
        assert_eq!(count, 0);
    }

    #[ktest]
    fn borrowed_limit_lowered_at_admission_single_cpu() {
        // Exercise both anonymous and VMO-backed actual mapping paths. The
        // companion POSIX probe covers file descriptors and syscall selection.
        for vmo_backed in [false, true] {
            let vmar = new_vmar();
            let base_size = vmar.get_mappings_total_size();
            let limit = RLimit64::new((base_size + PAGE_SIZE) as u64, RLIM_INFINITY);
            let borrowed_limit = &limit;
            let lower_limit = || set_cur(&limit, base_size);
            let mut options = vmar
                .new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
                .unwrap()
                .offset(ADDR, OffsetType::FixedNoReplace)
                .before_admission(&lower_limit);
            if vmo_backed {
                options = options.vmo(VmoOptions::new(PAGE_SIZE).alloc().unwrap());
            }
            assert_eq!(
                options
                    .build_with_rlimit_as(borrowed_limit)
                    .unwrap_err()
                    .error(),
                Errno::ENOMEM
            );
            assert_eq!(vmar.get_mappings_total_size(), base_size);
            assert_absent(&vmar, ADDR, PAGE_SIZE);
        }
    }

    #[ktest]
    fn borrowed_limit_raised_at_admission_single_cpu() {
        for vmo_backed in [false, true] {
            let vmar = new_vmar();
            let base_size = vmar.get_mappings_total_size();
            let limit = RLimit64::new(base_size as u64, RLIM_INFINITY);
            let borrowed_limit = &limit;
            let raise_limit = || set_cur(&limit, base_size + PAGE_SIZE);
            let mut options = vmar
                .new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
                .unwrap()
                .offset(ADDR, OffsetType::FixedNoReplace)
                .before_admission(&raise_limit);
            if vmo_backed {
                options = options.vmo(VmoOptions::new(PAGE_SIZE).alloc().unwrap());
            }
            assert_eq!(options.build_with_rlimit_as(borrowed_limit).unwrap(), ADDR);
            assert_present(&vmar, ADDR, PAGE_SIZE);
            assert_eq!(vmar.get_mappings_total_size(), base_size + PAGE_SIZE);
            vmar.remove_mapping(ADDR..ADDR + PAGE_SIZE).unwrap();
            assert_eq!(vmar.get_mappings_total_size(), base_size);
        }
    }

    #[ktest]
    fn borrowed_limit_fixed_replacement_accounting_single_cpu() {
        let vmar = new_vmar();
        let base_size = vmar.get_mappings_total_size();
        let limit = RLimit64::new((base_size + PAGE_SIZE) as u64, RLIM_INFINITY);
        for _ in 0..2 {
            assert_eq!(
                vmar.new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
                    .unwrap()
                    .offset(ADDR, OffsetType::Fixed)
                    .build_with_rlimit_as(&limit)
                    .unwrap(),
                ADDR
            );
            assert_present(&vmar, ADDR, PAGE_SIZE);
            assert_eq!(vmar.get_mappings_total_size(), base_size + PAGE_SIZE);
        }
        // Replacement removes the old mapping before admission, including on
        // failure. Preserve the baseline's resulting hole and accounting.
        set_cur(&limit, base_size);
        assert_eq!(
            vmar.new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
                .unwrap()
                .offset(ADDR, OffsetType::Fixed)
                .build_with_rlimit_as(&limit)
                .unwrap_err()
                .error(),
            Errno::ENOMEM
        );
        assert_absent(&vmar, ADDR, PAGE_SIZE);
        assert_eq!(vmar.get_mappings_total_size(), base_size);

        // A successful retry detects leaked quota from the failed admission.
        set_cur(&limit, base_size + PAGE_SIZE);
        vmar.new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
            .unwrap()
            .offset(ADDR, OffsetType::FixedNoReplace)
            .build_with_rlimit_as(&limit)
            .unwrap();
        vmar.remove_mapping(ADDR..ADDR + PAGE_SIZE).unwrap();
        assert_eq!(vmar.get_mappings_total_size(), base_size);
    }

    #[ktest]
    fn borrowed_limit_selected_per_call_on_shared_vmar_single_cpu() {
        let vmar = new_vmar();
        let shared_vmar = vmar.clone_handle();
        let base_size = vmar.get_mappings_total_size();
        let restrictive = RLimit64::new(base_size as u64, RLIM_INFINITY);
        let permissive = RLimit64::new((base_size + PAGE_SIZE) as u64, RLIM_INFINITY);
        assert_eq!(
            vmar.new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
                .unwrap()
                .offset(ADDR, OffsetType::FixedNoReplace)
                .build_with_rlimit_as(&restrictive)
                .unwrap_err()
                .error(),
            Errno::ENOMEM
        );
        shared_vmar
            .new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
            .unwrap()
            .offset(ADDR, OffsetType::FixedNoReplace)
            .build_with_rlimit_as(&permissive)
            .unwrap();
        assert_present(&vmar, ADDR, PAGE_SIZE);
        assert_eq!(vmar.get_mappings_total_size(), base_size + PAGE_SIZE);
        vmar.remove_mapping(ADDR..ADDR + PAGE_SIZE).unwrap();
        assert_eq!(shared_vmar.get_mappings_total_size(), base_size);
    }

    #[ktest]
    fn default_build_in_kernel_context_uses_infinity() {
        let vmar = new_vmar();
        let base_size = vmar.get_mappings_total_size();
        let addr = vmar
            .new_map(NonZeroUsize::new(PAGE_SIZE).unwrap(), VmPerms::READ)
            .unwrap()
            .build()
            .unwrap();
        assert_present(&vmar, addr, PAGE_SIZE);
        assert_eq!(vmar.get_mappings_total_size(), base_size + PAGE_SIZE);
        vmar.remove_mapping(addr..addr + PAGE_SIZE).unwrap();
        assert_eq!(vmar.get_mappings_total_size(), base_size);
    }
}

#[cfg(ktest)]
impl RLimit64 {
    pub(crate) fn new_for_accounting_test(cur: u64) -> Self {
        Self::new(cur, RLIM_INFINITY)
    }

    pub(crate) fn set_cur_for_accounting_test(&self, cur: u64) {
        self.set_raw_rlimit_unchecked(RawRLimit64 {
            cur,
            max: RLIM_INFINITY,
        });
    }
}
