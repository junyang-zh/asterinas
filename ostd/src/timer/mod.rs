// SPDX-License-Identifier: MPL-2.0

//! The timer support.

pub(crate) mod jiffies;

use alloc::{boxed::Box, vec, vec::Vec};

pub use jiffies::Jiffies;

use crate::{sync::RcuOption, trap::irq::DisabledLocalIrqGuard};

type InterruptCallback = fn(&DisabledLocalIrqGuard);

pub(crate) static INTERRUPT_CALLBACKS: RcuOption<Box<Vec<InterruptCallback>>> =
    RcuOption::new_none();

/// Register a function that will be executed during the system timer interruption.
pub fn register_callback(func: InterruptCallback) {
    loop {
        let guard = INTERRUPT_CALLBACKS.read();
        let new_callbacks;
        if let Some(copied_callbacks) = guard.get() {
            let mut cloned_callbacks = (*copied_callbacks).clone();
            cloned_callbacks.push(func);
            new_callbacks = Some(cloned_callbacks);
        } else {
            new_callbacks = Some(Box::new(vec![func]));
        }
        if guard.compare_exchange(new_callbacks).is_ok() {
            break;
        }
        core::hint::spin_loop();
    }
}
