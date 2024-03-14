// SPDX-License-Identifier: MPL-2.0

//! This module records the information of the the virtual memory layout of a process.
//! 
//! FIXME: The information here is pretty much unused. In the future refactoring process,
//! user stack and user heap should be additional information binded to specific Vmar.

pub mod user_heap;

use core::ops::DerefMut;

use align_ext::AlignExt;
use aster_frame::{sync::SpinLock, vm::config::PAGE_SIZE};
use aster_rights::Full;
use pod::Pod;
use user_heap::UserHeap;

use crate::{vm::vmar::Vmar, Vaddr};

pub const DEFAULT_USER_HEAP_SIZE_LIMIT: usize = PAGE_SIZE * 1000;

/*
 * The user's virtual memory space layout looks like below.
 *
 *  (high address)
 *  +---------------------+ <------+ The top of Vmar, which is the highest address usable
 *  | A reserved page     |          // FIXME: This should not be mappable but we neglected
 *  +---------------------+
 *  |                     |          0~255 randomly padded pages
 *  +---------------------+ <------+ The top of the initial user stack
 *  | User stack          |
 *  |                     |
 *  +---------||----------+ <------+ User stack top - ulimit, can be extended lower
 *  |         \/          |
 *  | ...                 |
 *  |                     |
 *  | MMAP Spaces         |
 *  |                     |
 *  | ...                 |
 *  |         /\          |
 *  +---------||----------+ <------+ The current program break
 *  | User heap           |
 *  |                     |
 *  +---------------------+ <------+ The original program break
 *  |                     |          0~255 randomly padded pages
 *  +---------------------+ <------+ The end of the program's last segment
 *  |                     |
 *  | Loaded segments     |
 *  | .text, .data, .bss  |
 *  | , etc.              |
 *  |                     |
 *  +---------------------+ <------+ The bottom of Vmar at 0x1_0000
 *  |                     |          64 KiB unusable space
 *  +---------------------+
 *  (low address)
 */

/// The virtual space usage.
/// This struct is used to control brk and mmap now.
pub struct ProcessVm {
    user_heap: SpinLock<Option<UserHeap>>,
    root_vmar: Vmar<Full>,
}

impl Clone for ProcessVm {
    fn clone(&self) -> Self {
        Self {
            root_vmar: self.root_vmar.dup().unwrap(),
            user_heap: SpinLock::new(self.user_heap.lock().as_ref().cloned()),
        }
    }
}

impl ProcessVm {
    pub fn alloc() -> Self {
        let root_vmar = Vmar::<Full>::new_root();
        ProcessVm {
            user_heap: SpinLock::new(None),
            root_vmar,
        }
    }

    pub fn new(user_heap: UserHeap, root_vmar: Vmar<Full>) -> Self {
        Self {
            user_heap: SpinLock::new(Some(user_heap)),
            root_vmar,
        }
    }

    pub fn user_heap(&self) -> &SpinLock<Option<UserHeap>> {
        &self.user_heap
    }

    pub fn replace_user_heap(&self, program_break: Vaddr) {
        let padded_break = {
            let mut nr_frames_padded: u8 = 0;
            getrandom::getrandom(nr_frames_padded.as_bytes_mut()).unwrap();
            program_break.align_up(PAGE_SIZE) + nr_frames_padded as usize * PAGE_SIZE
        };
        let user_heap = UserHeap::new(padded_break, DEFAULT_USER_HEAP_SIZE_LIMIT);
        user_heap.do_map(&self.root_vmar);
        *self.user_heap.lock().deref_mut() = Some(user_heap);
    }

    pub fn root_vmar(&self) -> &Vmar<Full> {
        &self.root_vmar
    }

    /// Set user vm to the init status
    pub fn clear(&self) {
        self.root_vmar.clear().unwrap();
        *self.user_heap.lock().deref_mut() = None;
    }
}
