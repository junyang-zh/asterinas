// SPDX-License-Identifier: MPL-2.0

//! Privileged diagnostic collector control: write 1 to start, 0 to stop.
//! Reads export immutable JSONL from a stopped epoch, never historical counters.

use aster_util::printer::VmPrinter;
use ostd::mm::breakdown;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps, read_u64_from},
        vfs::inode::Inode,
    },
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    security::lsm::hooks as lsm_hooks,
};

static SNAPSHOT: SpinLock<Option<Arc<str>>> = SpinLock::new(None);

pub(super) struct BreakdownCountersFileOps;

impl BreakdownCountersFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(u + rw))
    }
}

impl ProcFileOps for BreakdownCountersFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let data = SNAPSHOT
            .lock()
            .clone()
            .ok_or_else(|| Error::with_message(Errno::EBUSY, "stop collector before reading"))?;
        let mut printer = VmPrinter::new_skip(writer, offset);
        write!(printer, "{}", data)?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
            UserNamespace::get_init_singleton().as_ref(),
            current_thread!().as_posix_thread().unwrap(),
            CapSet::SYS_ADMIN,
        ))?;
        let (value, bytes) = read_u64_from(reader)?;
        match value {
            0 => breakdown::stop(),
            2 => breakdown::start_online(|| {
                aster_time::read_monotonic_time()
                    .as_nanos()
                    .try_into()
                    .unwrap_or(u64::MAX)
            }),
            1 | 64..=1_048_576 => breakdown::start(
                || {
                    aster_time::read_monotonic_time()
                        .as_nanos()
                        .try_into()
                        .unwrap_or(u64::MAX)
                },
                if value == 1 { 8192 } else { value as usize },
            ),
            _ => return_errno_with_message!(
                Errno::EINVAL,
                "write 0 to stop, 1 for raw defaults, 2 for online, or 64..1048576 events/CPU"
            ),
        }
        .map_err(|_| Error::with_message(Errno::EBUSY, "collector control unavailable"))?;
        let snapshot = if value == 0 {
            Some(Arc::<str>::from(breakdown::snapshot().map_err(|_| {
                Error::with_message(Errno::EBUSY, "collector snapshot unavailable")
            })?))
        } else {
            None
        };
        *SNAPSHOT.lock() = snapshot;
        Ok(bytes)
    }
}
