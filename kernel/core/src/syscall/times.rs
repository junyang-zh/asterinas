// SPDX-License-Identifier: MPL-2.0

use aster_time::read_monotonic_time;
use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{prelude::*, time::duration_to_user_ticks};

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct Tms {
    utime: i64,
    stime: i64,
    cutime: i64,
    cstime: i64,
}

pub(super) fn sys_times(buf: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    if buf != 0 {
        let clock = ctx.process.prof_clock();
        let (child_user, child_kernel) = ctx.process.reaped_children_stats().lock().get();
        let times = Tms {
            utime: duration_to_user_ticks(clock.user_clock().read_time()) as i64,
            stime: duration_to_user_ticks(clock.kernel_clock().read_time()) as i64,
            cutime: duration_to_user_ticks(child_user) as i64,
            cstime: duration_to_user_ticks(child_kernel) as i64,
        };
        ctx.user_space().write_val(buf, &times)?;
    }
    Ok(SyscallReturn::Return(duration_to_user_ticks(read_monotonic_time()) as _))
}
