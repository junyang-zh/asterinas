use alloc::vec::Vec;

use super::SyscallReturn;
use crate::{println, Context, Error};

pub fn sys_start_mem_profile(_ctx: &Context) -> Result<SyscallReturn, Error> {
    ostd::mm::start_mem_profile();
    Ok(SyscallReturn::Return(0))
}

pub fn sys_stop_mem_profile(_ctx: &Context) -> Result<SyscallReturn, Error> {
    let data = ostd::mm::stop_mem_profile();
    #[derive(serde::Serialize)]
    struct ProfileEntry {
        alloc_size: usize,
        stack: Vec<usize>,
        is_stack_complete: bool,
    }
    let parsed = data
        .into_iter()
        .map(|(_ptr, record)| {
            let mut stack = Vec::new();
            let mut is_stack_complete = false;
            for frame in record.stack.iter() {
                if *frame == 0 {
                    is_stack_complete = true;
                    break;
                }
                stack.push(*frame);
            }
            ProfileEntry {
                alloc_size: record.layout.size(),
                stack,
                is_stack_complete,
            }
        })
        .collect::<Vec<_>>();
    // Serialize the data and write it to the console
    let serialized = serde_json::to_string(&parsed).unwrap();
    println!("###DUMP_MEM_PROFILE_START###");
    println!("{}", serialized);
    println!("###DUMP_MEM_PROFILE_END###");
    Ok(SyscallReturn::Return(0))
}
