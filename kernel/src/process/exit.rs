// SPDX-License-Identifier: MPL-2.0

use ostd::task::Task;

use super::{process_table, signal::constants::SIGKILL, Pid, Process, TermStatus};
use crate::{
    prelude::*,
    process::{
        posix_thread::{do_exit, AsPosixThread},
        signal::signals::kernel::KernelSignal,
    },
};

/// Kills all threads and exits the current POSIX process.
///
/// # Panics
///
/// If the current thread is not a POSIX thread, this method will panic.
pub fn do_exit_group(term_status: TermStatus) {
    let current_task = Task::current().unwrap();
    let current_process = current_task.as_posix_thread().unwrap().process();

    if !current_process.status().set_exited_group() {
        // Another `exit_group` has been triggered and all the threads are being killed. Don't
        // update the exit code in this scenario.
        do_exit(None);
        return;
    }

    // Send `SIGKILL` to all other threads in the current process.
    for task in &*current_process.tasks().lock() {
        if !core::ptr::addr_eq(current_task.as_ref(), task.as_ref()) {
            task.as_posix_thread()
                .unwrap()
                .enqueue_signal(Box::new(KernelSignal::new(SIGKILL)));
        }
    }

    do_exit(Some(term_status));
}

/// Exits the current POSIX process.
///
/// This is for internal use. Do NOT call this directly. When the last thread in the process exits,
/// [`do_exit`] will invoke this method automatically.
pub(super) fn exit_process(current_process: &Process) {
    current_process.status().set_zombie();

    current_process.file_table().lock().close_all();

    send_parent_death_signal(current_process);

    move_children_to_init(current_process);

    send_child_death_signal(current_process);
}

/// Sends parent-death signals to the children.
//
// FIXME: According to the Linux implementation, the signal should be sent when the POSIX thread
// that created the child exits, not when the whole process exits. For more details, see the
// "CAVEATS" section in <https://man7.org/linux/man-pages/man2/pr_set_pdeathsig.2const.html>.
fn send_parent_death_signal(current_process: &Process) {
    for (_, child) in current_process.children().lock().iter() {
        let Some(signum) = child.parent_death_signal() else {
            continue;
        };

        // FIXME: Set `si_pid` in the `siginfo_t` argument.
        let signal = KernelSignal::new(signum);
        child.enqueue_signal(signal);
    }
}

/// Moves the children to the init process.
fn move_children_to_init(current_process: &Process) {
    if is_init_process(current_process) {
        return;
    }

    let Some(init_process) = get_init_process() else {
        return;
    };

    let mut init_children = init_process.children().lock();
    for (_, child_process) in current_process.children().lock().extract_if(|_, _| true) {
        let mut parent = child_process.parent.lock();
        init_children.insert(child_process.pid(), child_process.clone());
        parent.set_process(&init_process);
    }
}

/// Sends a child-death signal to the parent.
fn send_child_death_signal(current_process: &Process) {
    let Some(parent) = current_process.parent().lock().process().upgrade() else {
        return;
    };

    if let Some(signal) = current_process.exit_signal().map(KernelSignal::new) {
        parent.enqueue_signal(signal);
    };
    parent.children_wait_queue().wake_all();
}

const INIT_PROCESS_PID: Pid = 1;

/// Gets the init process
fn get_init_process() -> Option<Arc<Process>> {
    process_table::get_process(INIT_PROCESS_PID)
}

fn is_init_process(process: &Process) -> bool {
    process.pid() == INIT_PROCESS_PID
}
