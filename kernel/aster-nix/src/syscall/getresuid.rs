// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{prelude::*, process::credentials};

pub fn sys_getresuid(ruid_ptr: Vaddr, euid_ptr: Vaddr, suid_ptr: Vaddr) -> Result<SyscallReturn> {
    debug!("ruid_ptr = 0x{ruid_ptr:x}, euid_ptr = 0x{euid_ptr:x}, suid_ptr = 0x{suid_ptr:x}");

    let credentials = credentials();
    let user_space = CurrentUserSpace::get();

    let ruid = credentials.ruid();
    user_space.write_val(ruid_ptr, &ruid)?;

    let euid = credentials.euid();
    user_space.write_val(euid_ptr, &euid)?;

    let suid = credentials.suid();
    user_space.write_val(suid_ptr, &suid)?;

    Ok(SyscallReturn::Return(0))
}
