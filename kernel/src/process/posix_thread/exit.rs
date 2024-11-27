// SPDX-License-Identifier: MPL-2.0

use ostd::task::Task;

use super::{
    futex::futex_wake, robust_list::wake_robust_futex, thread_table, AsPosixThread, PosixThread,
};
use crate::{
    current_userspace,
    prelude::*,
    process::{exit::exit_process, TermStatus},
    thread::AsThread,
};

/// Exits the current POSIX thread.
///
/// # Panics
///
/// If the current thread is not a POSIX thread, this method will panic.
pub fn do_exit(term_status: Option<TermStatus>) {
    let current_task = Task::current().unwrap();
    let current_thread = current_task.as_thread().unwrap();

    // We should only change the thread status when running as the thread, so no race conditions
    // can occur in between.
    if current_thread.is_exited() {
        return;
    }
    current_thread.exit();

    let current_thread = current_thread.as_posix_thread().unwrap();
    let current_process = current_thread.process();

    // According to Linux's behavior, the last thread's exit code will become the process's exit
    // code, so here we should just overwrite the old value (if any).
    if let Some(term_status) = term_status {
        current_process.status().set_exit_code(term_status.as_u32());
    }

    let is_last_thread = {
        let mut tasks = current_process.tasks().lock();
        let current_index = tasks
            .iter()
            .position(|task| core::ptr::eq(task.as_ref(), current_task.as_ref()))
            .unwrap();
        tasks.swap_remove(current_index);

        tasks.is_empty()
    };

    wake_clear_ctid(current_thread);

    wake_robust_list(current_thread);

    // FIXME: According to Linux behavior, it seems that we shouldn't remove the main thread unless
    // the process is reaped by its parent. However, this makes it harder to track whether the
    // exiting thread is the last thread in the process.
    thread_table::remove_thread(current_thread.tid());

    if is_last_thread {
        exit_process(&current_process);
    }
}

/// Writes zero to `clear_child_tid` and performs a futex wake.
fn wake_clear_ctid(thread: &PosixThread) {
    let mut clear_ctid = thread.clear_child_tid().lock();

    if *clear_ctid == 0 {
        return;
    }

    let _ = current_userspace!()
        .write_val(*clear_ctid, &0u32)
        .inspect_err(|err| debug!("exit: cannot clear the child TID: {:?}", err));
    let _ = futex_wake(*clear_ctid, 1, None)
        .inspect_err(|err| debug!("exit: cannot wake the futex on the child TID: {:?}", err));

    *clear_ctid = 0;
}

/// Walks the robust futex list, marking futex dead and waking waiters.
///
/// This corresponds to Linux's `exit_robust_list`. Errors are silently ignored.
fn wake_robust_list(thread: &PosixThread) {
    let mut robust_list = thread.robust_list.lock();

    let list_head = match *robust_list {
        Some(robust_list_head) => robust_list_head,
        None => return,
    };

    trace!("exit: wake up the rubust list: {:?}", list_head);
    for futex_addr in list_head.futexes() {
        let _ = wake_robust_futex(futex_addr, thread.tid)
            .inspect_err(|err| debug!("exit: cannot wake up the robust futex: {:?}", err));
    }

    *robust_list = None;
}
