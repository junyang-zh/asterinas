//! VFS components

pub use access_mode::AccessMode;
pub use creation_flags::CreationFlags;
pub use dentry_cache::Dentry;
pub use dirent_writer::{DirentWriter, DirentWriterContext};
pub use fs::{FileSystem, SuperBlock};
pub use inode::{Inode, InodeMode, InodeType, Metadata, Timespec};
pub use page_cache::PageCacheManager;
pub use status_flags::StatusFlags;

mod access_mode;
mod creation_flags;
mod dentry_cache;
mod dirent_writer;
mod fs;
mod inode;
mod page_cache;
mod status_flags;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum SeekFrom {
    Start(u64),
    End(i64),
    Current(i64),
}

/// Maximum bytes in a path
pub const PATH_MAX: usize = 4096;

/// Maximum bytes in a file name
pub const NAME_MAX: usize = 255;

/// The upper limit for resolving symbolic links
pub const SYMLINKS_MAX: usize = 40;
