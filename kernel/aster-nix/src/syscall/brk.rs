// SPDX-License-Identifier: MPL-2.0

use core::ops::DerefMut;

use crate::{
    log_syscall_entry,
    prelude::*,
    syscall::{SyscallReturn, SYS_BRK},
    Errno::EINVAL,
};

/// expand the user heap to new heap end, returns the new heap end if expansion succeeds.
pub fn sys_brk(heap_end: u64) -> Result<SyscallReturn> {
    log_syscall_entry!(SYS_BRK);
    let new_heap_end = if heap_end == 0 {
        None
    } else {
        Some(heap_end as usize)
    };
    debug!("new heap end = {:x?}", heap_end);
    let current = current!();
    let mut user_heap = current.user_heap().lock();
    let Some(user_heap_ref) = user_heap.deref_mut() else {
        return_errno_with_message!(EINVAL, "user heap is not initialized.");
    };
    let new_heap_end = user_heap_ref.brk(new_heap_end)?;

    Ok(SyscallReturn::Return(new_heap_end as _))
}
