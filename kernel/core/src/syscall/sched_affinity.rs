// SPDX-License-Identifier: MPL-2.0

use ostd::{cpu::CpuSet, mm::VmIo};

use super::SyscallReturn;
use crate::{prelude::*, process::pid_table, thread::Tid};

pub(super) fn sys_sched_getaffinity(
    tid: Tid,
    cpuset_size: usize,
    cpu_set_ptr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let cpu_set = match tid {
        0 => ctx.thread.cpu_affinity(),
        _ => match pid_table::pid_table_mut().get_thread(tid) {
            Some(thread) => thread.cpu_affinity(),
            None => return_errno_with_message!(Errno::ESRCH, "the target thread does not exist"),
        },
    };

    let bytes_written = write_cpu_set_to(ctx.user_space(), &cpu_set, cpuset_size, cpu_set_ptr)?;

    Ok(SyscallReturn::Return(bytes_written as isize))
}

pub(super) fn sys_sched_setaffinity(
    tid: Tid,
    cpuset_size: usize,
    cpu_set_ptr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let user_cpu_set = read_cpu_set_from(ctx.user_space(), cpuset_size, cpu_set_ptr)?;

    if tid == 0 {
        ctx.thread.set_cpu_affinity(user_cpu_set, ctx.thread);
    } else {
        let target = pid_table::pid_table_mut().get_thread(tid)
            .ok_or_else(|| Error::with_message(Errno::ESRCH, "the target thread does not exist"))?;
        target.set_cpu_affinity(user_cpu_set, ctx.thread);
    }

    Ok(SyscallReturn::Return(0))
}

// Linux uses `DECLARE_BITMAP` for `cpu_set_t`, inside which each part is a
// `long`. We use the same scheme to ensure byte endianness compatibility.
type Part = u64;
const SIZE_OF_PART: usize = size_of::<Part>();

fn read_cpu_set_from(
    user_space: CurrentUserSpace,
    cpuset_size: usize,
    cpu_set_ptr: Vaddr,
) -> Result<CpuSet> {
    if cpuset_size == 0 {
        return_errno_with_message!(Errno::EINVAL, "invalid cpuset size");
    }

    let ret_set = CpuSet::try_from_words(|words| {
        let bytes = words.as_mut_bytes();
        let len = cpuset_size.min(bytes.len());
        user_space.read_bytes(cpu_set_ptr, &mut bytes[..len])
    })?;

    if ret_set.is_empty() {
        return_errno_with_message!(Errno::EINVAL, "empty cpuset");
    }

    Ok(ret_set)
}

// Returns the number of bytes written.
fn write_cpu_set_to(
    user_space: CurrentUserSpace,
    cpu_set: &CpuSet,
    cpuset_size: usize,
    cpu_set_ptr: Vaddr,
) -> Result<usize> {
    let words = cpu_set.as_words();
    if cpuset_size % SIZE_OF_PART != 0 || cpuset_size / SIZE_OF_PART < words.len() {
        return_errno_with_message!(Errno::EINVAL, "invalid cpuset size");
    }

    user_space.write_slice(cpu_set_ptr, words)?;
    Ok(size_of_val(words))
}
