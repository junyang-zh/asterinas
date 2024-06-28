// SPDX-License-Identifier: MPL-2.0

//! CPU local storage.
//!
//! This module provides a mechanism to define CPU-local objects.
//!
//! This is acheived by placing the CPU-local objects in a special section
//! `.cpu_local`. The bootstrap processor (BSP) uses the objects linked in this
//! section, and these objects are copied to dynamically allocated local
//! storage of each application processors (AP) during the initialization
//! process.
//!
//! Such a mechanism sadly exploits the fact that constant values of non-[`Copy`]
//! types can be bitwise copied. For example, a [`Option<T>`] object, though
//! being not [`Copy`], have a constant constructor [`Option::None`] that
//! produces a value that can be bitwise copied to create a new instance.
//! [`alloc::sync::Arc`] however, don't have such a constructor, and thus cannot
//! be directly used as a CPU-local object. Wrapping it in a type that has a
//! constant constructor, like [`Option<T>`], can make it CPU-local.

use core::ops::Deref;

use crate::cpu::{get_cpu_local_base, set_cpu_local_base};

/// Defines a CPU-local variable.
///
/// # Example
///
/// ```rust
/// use crate::cpu_local;
/// use core::cell::RefCell;
///
/// cpu_local! {
///     static FOO: RefCell<u32> = RefCell::new(1);
///
///     #[allow(unused)]
///     pub static BAR: RefCell<f32> = RefCell::new(1.0);
/// }
///
/// println!("FOO VAL: {:?}", *FOO.borrow());
/// ```
#[macro_export]
macro_rules! cpu_local {
    ($( $(#[$attr:meta])* $vis:vis static $name:ident: $t:ty = $init:expr; )*) => {
        $(
            #[allow(clippy::macro_metavars_in_unsafe)]
            #[link_section = ".cpu_local"]
            $(#[$attr])* $vis static $name: $crate::CpuLocal<$t> = unsafe { $crate::CpuLocal::new($init) };
        )*
    };
}

extern "C" {
    fn __cpu_local_start();
    fn __cpu_local_end();
}

/// CPU-local objects.
///
/// A CPU-local object only gives you immutable references to the underlying value.
/// To mutate the value, one can use atomic values (e.g., [`AtomicU32`]) or internally mutable
/// objects (e.g., [`RefCell`]).
///
/// [`AtomicU32`]: core::sync::atomic::AtomicU32
/// [`RefCell`]: core::cell::RefCell
pub struct CpuLocal<T>(T);

// SAFETY: At any given time, only one task can access the inner value T of a cpu-local variable.
unsafe impl<T> Sync for CpuLocal<T> {}

impl<T> CpuLocal<T> {
    /// Initialize a CPU-local object.
    ///
    /// Do not call this function directly. Instead, use the `cpu_local!` macro.
    ///
    /// # Safety
    ///
    /// The caller should ensure that the object initialized by this function resides in the
    /// `.cpu_local` section. Otherwise the behavior is undefined.
    #[doc(hidden)]
    pub const unsafe fn new(val: T) -> Self {
        Self(val)
    }

    /// Get access to the underlying value through a raw pointer.
    ///
    /// This function calculates the virtual address of the CPU-local object based on the per-
    /// cpu base address and the offset in the BSP.
    fn get(&self) -> *const T {
        let offset = {
            let bsp_va = self as *const _ as usize;
            let bsp_base = __cpu_local_start as usize;
            // The implementation should ensure that the CPU-local object resides in the `.cpu_local`.
            debug_assert!(bsp_va + core::mem::size_of::<T>() <= __cpu_local_end as usize);

            bsp_va - bsp_base as usize
        };

        let local_base = get_cpu_local_base() as usize;
        let local_va = local_base + offset;

        // A sanity check about the alignment.
        debug_assert_eq!(local_va % core::mem::align_of::<T>(), 0);

        local_va as *mut T
    }
}

impl<T> Deref for CpuLocal<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: it should be properly initialized before accesses.
        // And we do not create a mutable reference over it.
        unsafe { &*self.get() }
    }
}

/// Initializes the CPU local data for the bootstrap processor (BSP).
///
/// # Safety
///
/// It must be guaranteed that the BSP will not access local data before this function being called,
/// otherwise copying non-constant values will result in pretty bad undefined behavior.
pub unsafe fn init_as_bsp() {
    let start_base_va = __cpu_local_start as usize as u64;
    set_cpu_local_base(start_base_va);
}

#[cfg(ktest)]
mod test {
    use core::cell::RefCell;

    use ostd_macros::ktest;

    use super::*;

    #[ktest]
    fn test_cpu_local() {
        cpu_local! {
            static FOO: RefCell<usize> = RefCell::new(1);
            static BAR: RefCell<u8> = RefCell::new(3);
        }
        for _ in 0..10 {
            assert_eq!(*FOO.borrow(), 1);
            *FOO.borrow_mut() = 2;
            for _ in 0..10 {
                assert_eq!(*BAR.borrow(), 3);
                *BAR.borrow_mut() = 4;
                assert_eq!(*BAR.borrow(), 4);
                *BAR.borrow_mut() = 3;
            }
            assert_eq!(*FOO.borrow(), 2);
            *FOO.borrow_mut() = 1;
        }
    }
}
