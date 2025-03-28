// SPDX-License-Identifier: MPL-2.0

use crate::{prelude::*, syscall::SyscallReturn};

#[expect(unused)]
pub fn sys_futex(
    futex_addr: Vaddr,
    futex_op: i32,
    futex_val: u64,
    utime_addr: Vaddr,
    futex_new_addr: u64,
    bitset: u64,
    ctx: &Context,
) -> Result<SyscallReturn> {
    // Users will still check the FUTEX value even if the FUTEX_WAIT operation is not performed.
    Ok(SyscallReturn::Return(0))
}
