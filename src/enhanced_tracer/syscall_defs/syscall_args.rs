use crate::OsError;
use crate::StoppedProcess;
use std::ffi::OsString;
use std::io::{Error, ErrorKind};
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::os::raw::c_void;
use std::slice::from_raw_parts_mut;

use bitflags::bitflags;

pub trait FromStoppedProcess: Sized {
    fn from_process(process: &StoppedProcess, arg: u64) -> Result<Self, OsError>;
}

#[derive(Debug, Clone)]
pub enum DirectoryDescriptor {
    WorkingDirectory,
    FileDescriptor(i32),
}

bitflags! {
    pub struct OpenFlags: u64 {
        const O_RDONLY = 0;
        const O_WRONLY = 1;
        const O_RDWR = 2;
        const O_APPEND = 2000;
        // TODO: More flags
    }
}

bitflags! {
    pub struct OpenMode: u64 {
        const S_IRWXU = 00700;
        const S_IRUSR = 00400;
        const S_IWUSR = 00200;
        const S_IXUSR = 00100;
        const S_IRWXG = 00070;
        const S_IRGRP = 00040;
        const S_IWGRP = 00020;
        const S_IXGRP = 00010;
        const S_IRWXO = 00007;
        const S_IROTH = 00004;
        const S_IWOTH = 00002;
        const S_IXOTH = 00001;
    }
}

bitflags! {
    pub struct MmapProtection: u64 {
        const PROT_EXEC = libc::PROT_EXEC as u64;
        const PROT_READ = libc::PROT_READ as u64;
        const PROT_WRITE = libc::PROT_WRITE as u64;
        const PROT_NONE = libc::PROT_NONE as u64;
    }
}

bitflags! {
    pub struct MmapFlags: u64 {
        const MAP_32BIT = 0x40;
        const MAP_ANONYMOUS = 0x20;
        const MAP_DENYWRITE = 0x00800;
        const MAP_EXECUTABLE = 0x1000;
        const MAP_FILE = 0;
        const MAP_FIXED = 0x10;
        const MAP_GROWSDOWN = 0x00100;
        const MAP_HUGETLB = 0x40000;
        const MAP_LOCKED = 0x2000;
        const MAP_NONBLOCK = 0x10000;
        const MAP_NORESERVE = 0x4000;
        const MAP_POPULATE = 0x08000;
        const MAP_PRIVATE = 0x02;
        const MAP_SHARED = 0x01;
        const MAP_SHARED_VALIDATE = 0x03;
        const MAP_STACK = 0x20000;
        const MAP_SYNC = 0x80000;
        const MAP_UNINITIALIZED = 0x4000000;
    }
}

impl FromStoppedProcess for [*mut c_void; 512] {
    fn from_process(process: &StoppedProcess, arg: u64) -> Result<Self, Error> {
        let mut uninit = MaybeUninit::uninit();
        unsafe {
            let buffer = from_raw_parts_mut(uninit.as_mut_ptr() as *mut u8, size_of::<Self>());
            let n = process.read_in_child_vm(buffer, arg as *mut c_void)?;
            if n == 0 {
                return Err(OsError::from(ErrorKind::InvalidData));
            }
            Ok(uninit.assume_init())
        }
    }
}

impl FromStoppedProcess for OsString {
    fn from_process(process: &StoppedProcess, arg: u64) -> Result<Self, Error> {
        process.read_os_string_in_child_vm(arg as *mut c_void)
    }
}

impl FromStoppedProcess for Vec<OsString> {
    fn from_process(process: &StoppedProcess, arg: u64) -> Result<Self, Error> {
        let address_buffer: [*mut c_void; 512] = FromStoppedProcess::from_process(process, arg)?;
        let mut result = Vec::new();
        for &item_address in address_buffer.iter() {
            if item_address.is_null() {
                break;
            }
            result.push(FromStoppedProcess::from_process(
                process,
                item_address as u64,
            )?)
        }
        Ok(result)
    }
}

impl FromStoppedProcess for MmapFlags {
    fn from_process(_process: &StoppedProcess, arg: u64) -> Result<Self, Error> {
        Ok(MmapFlags::from_bits_truncate(arg))
    }
}

impl FromStoppedProcess for MmapProtection {
    fn from_process(_process: &StoppedProcess, arg: u64) -> Result<Self, Error> {
        Ok(MmapProtection::from_bits_truncate(arg))
    }
}

impl FromStoppedProcess for OpenFlags {
    fn from_process(_process: &StoppedProcess, arg: u64) -> Result<Self, Error> {
        Ok(OpenFlags::from_bits_truncate(arg))
    }
}

impl FromStoppedProcess for OpenMode {
    fn from_process(_process: &StoppedProcess, arg: u64) -> Result<Self, Error> {
        Ok(OpenMode::from_bits_truncate(arg))
    }
}

impl FromStoppedProcess for DirectoryDescriptor {
    fn from_process(_process: &StoppedProcess, arg: u64) -> Result<Self, Error> {
        let arg = arg as i32;
        let res = match arg {
            -100 => DirectoryDescriptor::WorkingDirectory,
            x => DirectoryDescriptor::FileDescriptor(x),
        };
        Ok(res)
    }
}
