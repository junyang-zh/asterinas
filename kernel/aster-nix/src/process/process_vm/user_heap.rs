// SPDX-License-Identifier: MPL-2.0

use align_ext::AlignExt;
use aster_rights::{Full, Rights};

use crate::{
    prelude::*,
    vm::{
        perms::VmPerms,
        vmar::Vmar,
        vmo::{VmoFlags, VmoOptions},
    },
    Vaddr,
};

/// FIXME: The user heap is designed like a mess...
/// The code is actually broken, it just looks like the case.
/// Modern applications are not using brk anymore, so it works fine.
#[derive(Debug)]
pub struct UserHeap {
    /// the low address of user heap
    heap_base: Vaddr,
    /// the max heap size
    heap_size_limit: usize,
    current_heap_end: usize,
    // WHY don't you own the Vmo?
}

impl UserHeap {
    pub fn new(heap_base: Vaddr, heap_size_limit: usize) -> Self {
        Self {
            heap_base,
            heap_size_limit,
            current_heap_end: heap_base,
        }
    }

    pub fn do_map(&self, root_vmar: &Vmar<Full>) -> Vaddr {
        let perms = VmPerms::READ | VmPerms::WRITE;
        let vmo_options = VmoOptions::<Rights>::new(0).flags(VmoFlags::RESIZABLE);
        let heap_vmo = vmo_options.alloc().unwrap();
        let vmar_map_options = root_vmar
            .new_map(heap_vmo, perms)
            .unwrap()
            .offset(self.heap_base)
            .size(self.heap_size_limit);
        vmar_map_options.build().unwrap();
        self.current_heap_end
    }

    pub fn brk(&mut self, new_heap_end: Option<Vaddr>) -> Result<Vaddr> {
        let current = current!();
        let root_vmar = current.root_vmar();
        match new_heap_end {
            None => Ok(self.current_heap_end),
            Some(new_heap_end) => {
                if new_heap_end > self.heap_base + self.heap_size_limit {
                    return_errno_with_message!(Errno::ENOMEM, "heap size limit was met.");
                }
                let current_heap_end = self.current_heap_end;
                if new_heap_end < current_heap_end {
                    // FIXME: should we allow shrink current user heap?
                    return Ok(current_heap_end);
                }
                let new_size = (new_heap_end - self.heap_base).align_up(PAGE_SIZE);
                let heap_mapping = root_vmar.get_vm_mapping(self.heap_base)?;
                let heap_vmo = heap_mapping.vmo();
                heap_vmo.resize(new_size)?;
                self.current_heap_end = new_heap_end;
                Ok(new_heap_end)
            }
        }
    }
}

impl Clone for UserHeap {
    fn clone(&self) -> Self {
        Self {
            heap_base: self.heap_base,
            heap_size_limit: self.heap_size_limit,
            current_heap_end: self.current_heap_end,
        }
    }
}
