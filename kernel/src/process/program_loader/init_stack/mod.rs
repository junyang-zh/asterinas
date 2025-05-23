// SPDX-License-Identifier: MPL-2.0

//! Initializing/reading the initial stack for the process.
//!
//! Upon the user program entry, the initial stack passes the `argv` and `envp`
//! and auxiliary vectors to the user. Assuming a grows-down stack, the lowest
//! address of initial stack is the entry stack pointer (`rsp` in x86_64) of
//! the first user thread.
//!
//! The init stack will be mapped to user space and the user process can write
//! the content of init stack, so the content reading from init stack may not
//! be the same as the process' initial status.
//!
//! Upon the entry of the user program, the stack layout is as follows:
//!
//! ```text
//!  (high address)
//!  +---------------------+ <------+ Highest address
//!  |                     |          Random stack paddings
//!  +---------------------+ <------+ The base of stack (stack grows down)
//!  |                     |
//!  | Null-terminated     |
//!  | strings referenced  |
//!  | by variables below  |
//!  |                     |
//!  +---------------------+
//!  | AT_NULL             |
//!  +---------------------+
//!  | AT_NULL             |
//!  +---------------------+
//!  | ...                 |
//!  +---------------------+
//!  | aux_val[0]          |
//!  +---------------------+
//!  | aux_key[0]          | <------+ Auxiliary table
//!  +---------------------+
//!  | NULL                |
//!  +---------------------+
//!  | ...                 |
//!  +---------------------+
//!  | char* envp[0]       | <------+ Environment variables
//!  +---------------------+
//!  | NULL                |
//!  +---------------------+
//!  | char* argv[argc-1]  |
//!  +---------------------+
//!  | ...                 |
//!  +---------------------+
//!  | char* argv[0]       |
//!  +---------------------+
//!  | long argc           | <------+ Program arguments
//!  +---------------------+
//!  |                     |
//!  |                     |
//!  +---------------------+
//!  |                     |
//!  +---------------------+ <------+ User stack default rlimit
//!  (low address)
//! ```

use align_ext::AlignExt;
use aster_rights::Full;
use ostd::mm::{vm_space::VmItem, UntypedMem, VmIo, MAX_USERSPACE_VADDR};

use self::aux_vec::{AuxKey, AuxVec};
use crate::{
    prelude::*,
    process::process_vm::ProcessVmarGuard,
    util::random::getrandom,
    vm::{
        perms::VmPerms,
        vmar::Vmar,
        vmo::{Vmo, VmoOptions, VmoRightsOp},
    },
};

pub mod aux_vec;

/// Set the initial stack size to 8 megabytes, following the default Linux stack size limit.
pub const INIT_STACK_MAX_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// The max number of arguments that can be used to creating a new process.
pub const MAX_ARGV_NUMBER: usize = 128;
/// The max number of environmental variables that can be used to creating a new process.
pub const MAX_ENVP_NUMBER: usize = 128;
/// The max length of each argument to create a new process.
pub const MAX_ARG_LEN: usize = 2048;
/// The max length of each environmental variable (the total length of key-value pair) to create a new process.
pub const MAX_ENV_LEN: usize = 128;

/// The virtual address of the initial stack.
#[derive(Debug, Clone, Copy)]
pub struct InitStackPos {
    /// The initial highest stack pointer.
    ///
    /// The stack grows down from this address.
    top_addr: Vaddr,
    /// The stack pointer position upon the entry of the process.
    entry_addr: Vaddr,
}

impl InitStackPos {
    /// Returns the topmost address of the initial stack.
    pub fn top_addr(&self) -> Vaddr {
        self.top_addr
    }

    /// Returns the stack pointer upon the entry of the user process.
    pub fn entry_addr(&self) -> Vaddr {
        self.entry_addr
    }
}

/// Maps the initial stack into the [`Vmar`] and writes the initial stack content.
///
/// It returns the [`InitStackPos`] which is the position of the initial stack.
/// in the [`Vmar`].
pub fn map_and_init_init_stack(
    vmar: &Vmar<Full>,
    argv: Vec<CString>,
    envp: Vec<CString>,
    auxvec: AuxVec,
) -> Result<InitStackPos> {
    let top_addr = rand_init_stack_top();
    let max_size = INIT_STACK_MAX_SIZE;
    let map_addr = top_addr - max_size;

    let vmo = {
        let vmo_options = VmoOptions::<Full>::new(INIT_STACK_MAX_SIZE);
        vmo_options.alloc()?
    };
    let vmar_map_options = {
        let perms = VmPerms::READ | VmPerms::WRITE;
        root_vmar
            .new_map(max_size, perms)?
            .offset(map_addr)
            .vmo(vmo.dup().to_dyn())
    };
    vmar_map_options.build()?;

    let writer = InitStackWriter {
        pos: top_addr,
        vmo,
        argv,
        envp,
        auxvec,
        map_addr,
    };

    writer.write()?;

    Ok(InitStackPos {
        top_addr,
        entry_addr: writer.pos,
    })
}

fn rand_init_stack_top() -> Vaddr {
    let nr_pages_padding = {
        // We do not want the stack top too close to MAX_USERSPACE_VADDR.
        // So we add this fixed padding. Any small value greater than zero will do.
        const NR_FIXED_PADDING_PAGES: usize = 7;

        // Some random padding pages are added as a simple measure to
        // make the stack values of a buggy user program harder
        // to be exploited by attackers.
        let mut nr_random_padding_pages: u8 = 0;
        getrandom(nr_random_padding_pages.as_bytes_mut()).unwrap();

        nr_random_padding_pages as usize + NR_FIXED_PADDING_PAGES
    };

    MAX_USERSPACE_VADDR - PAGE_SIZE * nr_pages_padding
}

/// A reader to parse the content from the user's initial stack.
pub struct InitStackReader<'a> {
    pos: InitStackPos,
    vmar: ProcessVmarGuard<'a>,
}

impl InitStackReader<'_> {
    /// Creates a reader to read the initial stack.
    pub fn new(pos: InitStackPos, vmar: ProcessVmarGuard<'_>) -> Result<Self> {
        Ok(InitStackReader { pos, vmar })
    }

    /// Reads argc from the process init stack
    pub fn argc(&self) -> Result<u64> {
        let entry_addr = self.pos.entry_addr();
        let entry_page_base = entry_addr.align_down(PAGE_SIZE);

        let vm_space = self.vmar.unwrap().vm_space();
        let mut cursor = vm_space.cursor(&(entry_page_base..entry_page_base + PAGE_SIZE))?;
        let VmItem::Mapped { frame, .. } = cursor.query()? else {
            return_errno_with_message!(Errno::EACCES, "Page not accessible");
        };

        let argc = frame.read_val::<u64>(entry_addr - entry_page_base)?;
        if argc > MAX_ARGV_NUMBER as u64 {
            return_errno_with_message!(Errno::EINVAL, "argc is corrupted");
        }

        Ok(argc)
    }

    /// Reads argv from the process init stack
    pub fn argv(&self) -> Result<Vec<CString>> {
        let argc = self.argc()? as usize;
        // The reading offset in the initial stack is:
        // the initial stack bottom address + the size of `argc` in memory
        let read_offset = self.pos.entry_addr() + size_of::<usize>();
        let entry_page_base = entry_addr.align_down(PAGE_SIZE);

        let mut argv = Vec::with_capacity(argc);

        let vm_space = self.vmar.unwrap().vm_space();
        let mut cursor = vm_space.cursor(&(entry_page_base..entry_page_base + PAGE_SIZE))?;
        let VmItem::Mapped { frame, .. } = cursor.query()? else {
            return_errno_with_message!(Errno::EACCES, "Page not accessible");
        };

        let mut arg_ptr_reader = frame.reader();
        arg_ptr_reader.skip(read_offset - entry_page_base);
        for _ in 0..argc {
            let arg = {
                let arg_ptr = arg_ptr_reader.read_val::<Vaddr>()?;
                let arg_offset = arg_ptr
                    .checked_sub(entry_page_base)
                    .ok_or_else(|| Error::with_message(Errno::EINVAL, "arg_ptr is corrupted"))?;
                let mut arg_reader = frame.reader().to_fallible();
                arg_reader.skip(arg_offset).limit(MAX_ARG_LEN);
                arg_reader.read_cstring()?
            };
            argv.push(arg);
        }

        Ok(argv)
    }

    /// Reads envp from the process
    pub fn envp(&self) -> Result<Vec<CString>> {
        let argc = self.argc()? as usize;
        // The reading offset in the initial stack is:
        // the initial stack entry address
        //  + the size of argc(8)
        //  + the size of arg pointer(8) * the number of arg(argc)
        //  + the size of null pointer(8)
        let read_offset = self.pos.entry_addr()
            + size_of::<usize>()
            + size_of::<usize>() * argc
            + size_of::<usize>();

        let mut envp = Vec::new();
        let entry_page_base = read_offset.align_down(PAGE_SIZE);

        let vm_space = self.vmar.unwrap().vm_space();
        let mut cursor = vm_space.cursor(&(entry_page_base..entry_page_base + PAGE_SIZE))?;
        let VmItem::Mapped { frame, .. } = cursor.query()? else {
            return_errno_with_message!(Errno::EACCES, "Page not accessible");
        };

        let mut envp_ptr_reader = frame.reader();
        envp_ptr_reader.skip(read_offset - entry_page_base);
        for _ in 0..MAX_ENVP_NUMBER {
            let env = {
                let envp_ptr = envp_ptr_reader.read_val::<Vaddr>()?;

                if envp_ptr == 0 {
                    break;
                }

                let envp_offset = envp_ptr
                    .checked_sub(entry_page_base)
                    .ok_or_else(|| Error::with_message(Errno::EINVAL, "envp is corrupted"))?;
                let mut envp_reader = frame.reader().to_fallible();
                envp_reader.skip(envp_offset).limit(MAX_ENV_LEN);
                envp_reader.read_cstring()?
            };
            envp.push(env);
        }

        Ok(envp)
    }
}

/// A user-space writer to initialize the initial stack.
struct InitStackWriter {
    /// The writer's current position.
    pos: Vaddr,
    vmo: Vmo<Full>,
    argv: Vec<CString>,
    envp: Vec<CString>,
    auxvec: AuxVec,
    /// The mapping address of the `InitStackPos`.
    map_addr: usize,
}

impl InitStackWriter {
    fn write(mut self) -> Result<()> {
        // FIXME: Some OSes may put the first page of executable file here
        // for interpreting elf headers.

        let argc = self.argv.len() as u64;

        // Write envp string
        let envp_pointers = self.write_envp_strings()?;
        // Write argv string
        let argv_pointers = self.write_argv_strings()?;
        // Generate random values for auxvec
        let random_value_pointer = {
            let random_value = generate_random_for_aux_vec();
            self.write_bytes(&random_value)?
        };
        self.auxvec.set(AuxKey::AT_RANDOM, random_value_pointer)?;

        self.adjust_stack_alignment(&envp_pointers, &argv_pointers)?;
        self.write_aux_vec()?;
        self.write_envp_pointers(envp_pointers)?;
        self.write_argv_pointers(argv_pointers)?;

        // write argc
        self.write_u64(argc)?;

        // Ensure stack top is 16-bytes aligned
        debug_assert_eq!(self.pos & !0xf, self.pos);

        Ok(())
    }

    fn write_envp_strings(&mut self) -> Result<Vec<u64>> {
        let mut envp_pointers = Vec::with_capacity(self.envp.len());
        for envp in self.envp.iter() {
            let pointer = self.write_cstring(envp)?;
            envp_pointers.push(pointer);
        }
        Ok(envp_pointers)
    }

    fn write_argv_strings(&mut self) -> Result<Vec<u64>> {
        let mut argv_pointers = Vec::with_capacity(self.argv.len());
        for argv in self.argv.iter().rev() {
            let pointer = self.write_cstring(argv)?;
            debug!("argv address = 0x{:x}", pointer);
            argv_pointers.push(pointer);
        }
        argv_pointers.reverse();
        Ok(argv_pointers)
    }

    /// Libc ABI requires 16-byte alignment of the stack entrypoint.
    /// Current position of the stack is 8-byte aligned already, insert 8 byte
    /// to meet the requirement if necessary.
    fn adjust_stack_alignment(
        &mut self,
        envp_pointers: &[u64],
        argv_pointers: &[u64],
    ) -> Result<()> {
        // Ensure 8-byte alignment
        self.write_u64(0)?;
        let auxvec_size = (self.auxvec.table().len() + 1) * (mem::size_of::<u64>() * 2);
        let envp_pointers_size = (envp_pointers.len() + 1) * mem::size_of::<u64>();
        let argv_pointers_size = (argv_pointers.len() + 1) * mem::size_of::<u64>();
        let argc_size = mem::size_of::<u64>();
        let to_write_size = auxvec_size + envp_pointers_size + argv_pointers_size + argc_size;
        if (self.pos - to_write_size) % 16 != 0 {
            self.write_u64(0)?;
        }
        Ok(())
    }

    fn write_aux_vec(&mut self) -> Result<()> {
        // Write NULL auxiliary
        self.write_u64(0)?;
        self.write_u64(AuxKey::AT_NULL as u64)?;
        // Write Auxiliary vectors
        let aux_vec: Vec<_> = self
            .auxvec
            .table()
            .iter()
            .map(|(aux_key, aux_value)| (*aux_key, *aux_value))
            .collect();
        for (aux_key, aux_value) in aux_vec.iter() {
            self.write_u64(*aux_value)?;
            self.write_u64(*aux_key as u64)?;
        }
        Ok(())
    }

    fn write_envp_pointers(&mut self, mut envp_pointers: Vec<u64>) -> Result<()> {
        // write NULL pointer
        self.write_u64(0)?;
        // write envp pointers
        envp_pointers.reverse();
        for envp_pointer in envp_pointers {
            self.write_u64(envp_pointer)?;
        }
        Ok(())
    }

    fn write_argv_pointers(&mut self, mut argv_pointers: Vec<u64>) -> Result<()> {
        // write 0
        self.write_u64(0)?;
        // write argv pointers
        argv_pointers.reverse();
        for argv_pointer in argv_pointers {
            self.write_u64(argv_pointer)?;
        }
        Ok(())
    }

    /// Writes u64 to the stack.
    /// Returns the writing address
    fn write_u64(&mut self, val: u64) -> Result<u64> {
        let start_address = (self.pos - 8).align_down(8);
        self.pos = start_address;
        self.vmo.write_val(start_address - self.map_addr, &val)?;
        Ok(self.pos as u64)
    }

    /// Writes a CString including the ending null byte to the stack.
    /// Returns the writing address
    fn write_cstring(&mut self, val: &CString) -> Result<u64> {
        let bytes = val.as_bytes_with_nul();
        self.write_bytes(bytes)
    }

    /// Writes u64 to the stack.
    /// Returns the writing address.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<u64> {
        let len = bytes.len();
        self.pos -= len;
        self.vmo.write_bytes(self.pos - self.map_addr, bytes)?;
        Ok(pos as u64)
    }
}

fn generate_random_for_aux_vec() -> [u8; 16] {
    let mut rand_val = [0; 16];
    getrandom(&mut rand_val).unwrap();
    rand_val
}
