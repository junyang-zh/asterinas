// SPDX-License-Identifier: MPL-2.0

//! A configuration module for framework memory management.

use super::Vaddr;

pub const KERNEL_STACK_SIZE: usize = PAGE_SIZE * 64;
pub const KERNEL_HEAP_SIZE: usize = PAGE_SIZE * 256;

/// Typicall 64-bit systems have at least 48-bit virtual address space.
/// Halving it to reserve half of the address space for the kernel.
/// TODO: Consider shrinking it if exotic architectures are supported.
pub const USERSPACE_LOWEST_UNUSABLE_VADDR: Vaddr = 0x0000_8000_0000_0000;

// FIXME: the following constants are all architecture dependent. Need
// a proper redesign.

/// The kernel code is linear mapped to this address.
///
/// FIXME: This offset should be randomly chosen by the loader or the
/// boot compatibility layer. But we disabled it because the framework
/// doesn't support relocatable kernel yet.
pub fn kernel_loaded_offset() -> usize {
    0xffff_ffff_8000_0000
}

/// The canonical higher half offset of x86_64. See
/// <https://www.kernel.org/doc/html/latest/arch/x86/x86_64/mm.html>
/// for more details.
///
/// We use this offset to manage the physical memory starting from 0x0.
pub const KERNEL_PHYS_SPACE_OFFSET: usize = 0xffff_8000_0000_0000;

/// They should be the properties of IA32E regular pages.
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;
