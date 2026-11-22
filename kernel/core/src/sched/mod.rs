// SPDX-License-Identifier: MPL-2.0

mod nice;
mod sched_class;
mod stats;

#[cfg(feature = "artifact_busy_poll")]
pub(crate) use self::sched_class::register_polling_idle;
pub(crate) use self::{
    nice::{AtomicNice, Nice},
    sched_class::{
        LinuxSchedPolicy, RealTimePolicy, RealTimePriority, SchedAttr, SchedPolicy, init,
        init_on_each_cpu, steal_a_task,
    },
    stats::{loadavg, nr_queued_and_running},
};
