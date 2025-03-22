// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;
use core::{ptr::NonNull, sync::atomic::Ordering};

use super::{context_switch, Task, TaskContext, POST_SCHEDULE_HANDLER};
use crate::cpu_local_cell;

cpu_local_cell! {
    /// The `Arc<Task>` (casted by [`Arc::into_raw`]) that is the current task.
    static CURRENT_TASK_PTR: *const Task = core::ptr::null();
    /// The previous task on the processor before switching to the current task.
    /// It is used for delayed resource release since it would be the current
    /// task's job to recycle the previous resources.
    static PREVIOUS_TASK_PTR: *const Task = core::ptr::null();
    /// An unsafe cell to store the context of the bootstrap code.
    static BOOTSTRAP_CONTEXT: TaskContext = TaskContext::new();
}

/// Returns a pointer to the current task running on the processor.
///
/// It returns `None` if the function is called in the bootstrap context.
pub(super) fn current_task() -> Option<NonNull<Task>> {
    NonNull::new(CURRENT_TASK_PTR.load().cast_mut())
}

/// Calls this function to switch to other task
///
/// If current task is none, then it will use the default task context and it
/// will not return to this function again.
///
/// # Panics
///
/// This function will panic if called while holding preemption locks or with
/// local IRQ disabled.
#[track_caller]
pub(super) fn switch_to_task(next_task: Arc<Task>) {
    super::atomic_mode::might_sleep();

    // SAFETY: RCU read-side critical sections disables preemption. By the time
    // we reach this point, we have already checked that preemption is enabled.
    unsafe {
        crate::sync::finish_grace_period();
    }

    // Keep interrupts disabled during context switching. This will be enabled
    // after switching to the target task (in `on_task_entry`).
    crate::arch::irq::disable_local();

    // Set the running CPU of the next task.
    let cur_cpuid = crate::cpu::current_cpu_racy(); // Safe since IRQs are disabled.
    while next_task
        .running_on_cpu
        .compare_exchange(None, Some(cur_cpuid), Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        // Might be a scheduler bug.
        log::warn!("Switching to a task that is already running on another CPU");
        core::hint::spin_loop();
    }

    let current_task_ptr = CURRENT_TASK_PTR.load();
    let current_task_ctx_ptr = if !current_task_ptr.is_null() {
        // SAFETY: The current task is always alive.
        let current_task = unsafe { &*current_task_ptr };
        current_task.save_fpu_state();

        // Throughout this method, the task's context is alive and can be exclusively used.
        current_task.ctx.get()
    } else {
        // Throughout this method, interrupts are disabled and the context can be exclusively used.
        BOOTSTRAP_CONTEXT.as_mut_ptr()
    };

    let next_task_ctx_ptr = next_task.ctx().get().cast_const();

    // Change the current task to the next task.
    //
    // We cannot directly drop `current` at this point. Since we are running as
    // `current`, we must avoid dropping `current`. Otherwise, the kernel stack
    // may be unmapped, leading to instant failure.
    let old_prev = PREVIOUS_TASK_PTR.load();
    PREVIOUS_TASK_PTR.store(current_task_ptr);
    CURRENT_TASK_PTR.store(Arc::into_raw(next_task));

    if let Some(handler) = POST_SCHEDULE_HANDLER.get() {
        handler();
    }

    // Drop the old-previously running task.
    if !old_prev.is_null() {
        // SAFETY: The pointer is set by `switch_to_task` and is guaranteed to be
        // built with `Arc::into_raw`.
        drop(unsafe { Arc::from_raw(old_prev) });
    }

    // SAFETY:
    // 1. `ctx` is only used in `reschedule()`. We have exclusive access to both the current task
    //    context and the next task context.
    // 2. The next task context is a valid task context.
    unsafe {
        // This function may not return, for example, when the current task exits. So make sure
        // that all variables on the stack can be forgotten without causing resource leakage.
        context_switch(current_task_ctx_ptr, next_task_ctx_ptr);
    }

    // Now it's fine to drop `prev_task`. However, we choose not to do this because it is not
    // always possible. For example, `context_switch` can switch directly to the entry point of the
    // next task. Not dropping is just fine because the only consequence is that we delay the drop
    // to the next task switching.

    on_task_entry();

    // The `next_task` was moved into `CURRENT_TASK_PTR` above, now restore its FPU state.
    if let Some(current) = Task::current() {
        current.restore_fpu_state();
    }
}

/// The function to be called when a task is entered/resumed.
pub(super) fn on_task_entry() {
    let prev_task_ptr = PREVIOUS_TASK_PTR.load();
    if !prev_task_ptr.is_null() {
        // SAFETY: The pointer is set by `switch_to_task` and is guaranteed to be
        // built with `Arc::into_raw`. If this is not NULL the pointer must be valid.
        let prev_task = unsafe { &*prev_task_ptr };
        #[cfg(debug_assertions)]
        {
            let prev = prev_task.running_on_cpu.swap(None, Ordering::Release);
            debug_assert_eq!(prev, Some(crate::cpu::current_cpu_racy()));
        }
        #[cfg(not(debug_assertions))]
        {
            prev_task.running_on_cpu.store(None, Ordering::Release);
        }
    }

    crate::arch::irq::enable_local();
}
