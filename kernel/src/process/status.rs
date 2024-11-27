// SPDX-License-Identifier: MPL-2.0

//! The process status.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::ExitCode;

/// The status of a process.
///
/// This maintains:
/// 1. Whether an `exit_group` has been initiated from a thread;
/// 2. Whether the process is a zombie (i.e., all its threads have exited);
/// 3. The exit code of the process.
#[derive(Debug)]
pub struct ProcessStatus {
    has_exited_group: AtomicBool,
    is_zombie: AtomicBool,
    exit_code: AtomicU32,
}

impl Default for ProcessStatus {
    fn default() -> Self {
        Self {
            has_exited_group: AtomicBool::new(false),
            is_zombie: AtomicBool::new(false),
            exit_code: AtomicU32::new(0),
        }
    }
}

impl ProcessStatus {
    /// Returns whether an `exit_group` has been initiated.
    pub(super) fn has_exited_group(&self) -> bool {
        self.has_exited_group.load(Ordering::Relaxed)
    }

    /// Sets a flag that denotes that an `exit_group` has been initiated.
    ///
    /// The `exit_group` system call can occur multiple times if multiple threads trigger it at the
    /// same time, or if the process is killed asynchronously. This method will only return true
    /// for the first one.
    pub(super) fn set_exited_group(&self) -> bool {
        !self.has_exited_group.swap(true, Ordering::Relaxed)
    }
}

impl ProcessStatus {
    /// Returns whether the process is a zombie process.
    pub fn is_zombie(&self) -> bool {
        // Use the `Acquire` memory order to make the exit code visible.
        self.is_zombie.load(Ordering::Acquire)
    }

    /// Sets the process to be a zombie process.
    ///
    /// This method should be called when the process completes its exit. The current thread must
    /// be the last thread in the process, so that no threads belonging to the process can run
    /// after it.
    pub(super) fn set_zombie(&self) {
        // Use the `Release` memory order to make the exit code visible.
        self.is_zombie.store(true, Ordering::Release);
    }
}

impl ProcessStatus {
    /// Returns the exit code.
    pub fn exit_code(&self) -> ExitCode {
        self.exit_code.load(Ordering::Relaxed)
    }

    /// Sets the exit code.
    pub(super) fn set_exit_code(&self, exit_code: ExitCode) {
        self.exit_code.store(exit_code, Ordering::Relaxed);
    }
}
