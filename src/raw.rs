use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::mem::size_of;
use std::os::raw::{c_int, c_ulonglong};
use std::os::raw::c_long;
use std::os::raw::c_void;
use std::ptr::null_mut;

use libc::close;
use libc::O_CLOEXEC;
use libc::pid_t;
use libc::pipe2;
use libc::ptrace;
use libc::read;
use libc::waitpid;

use crate::OsError;

pub type PTraceRequest = libc::c_uint;

pub fn wait_pid(pid: pid_t, options: c_int) -> Result<(pid_t, c_int), OsError> {
    let mut status = 0;

    match unsafe { waitpid(pid, &mut status as *mut c_int, options) } {
        -1 => Err(OsError::last_os_error()),
        x => Ok((x, status))
    }
}

pub unsafe fn p_trace(req: PTraceRequest, pid: pid_t, addr: Option<*mut c_void>, data: Option<*mut c_void>) -> Result<c_long, OsError> {
    match ptrace(req, pid, addr.unwrap_or(null_mut()), data.unwrap_or(null_mut())) {
        -1 => Err(OsError::last_os_error()),
        x => Ok(x)
    }
}

pub unsafe fn fork() -> Result<ForkResult, OsError> {
    match libc::fork() {
        -1 => Err(OsError::last_os_error()),
        0 => Ok(ForkResult::Child),
        child_pid => Ok(ForkResult::Parent { child_pid })
    }
}

pub fn get_syscall_number(child_pid: pid_t) -> Result<i64, OsError> {
    let mut regs = MaybeUninit::<UserRegs>::uninit();
    let size = std::mem::size_of_val(&regs);

    let mut iovec = IOVec {
        iov_base: regs.as_mut_ptr() as *mut c_void,
        iov_len: size,
    };
    let regs = unsafe {
        p_trace(libc::PTRACE_GETREGSET, child_pid, Some(1 as *mut c_void), Some(&mut iovec as *mut IOVec as *mut c_void))?;
        regs.assume_init()
    };

    unsafe {
        match (iovec.iov_len, regs) {
            (size, UserRegs { x86 }) if size == size_of::<UserRegsX86>() => Ok(x86.orig_eax as i64),
            (size, UserRegs { amd64 }) if size == size_of::<UserRegsAMD64>() => Ok(amd64.orig_rax as i64),
            _ => Err(OsError::new(ErrorKind::Other, "Got unexpected size of payload for PTRACE_GETREGSET")),
        }
    }
}


pub unsafe fn pipe() -> Result<(c_int, c_int), OsError> {
    let mut result = [0, 0];
    match pipe2(result.as_mut_ptr(), O_CLOEXEC) {
        -1 => Err(OsError::last_os_error()),
        // index 0 is the read end, 1 is the write end
        _ => Ok((result[1], result[0]))
    }
}

pub unsafe fn read_wait(fd: c_int) -> Result<(), OsError> {
    let mut buf = [0u8];
    match read(fd, buf.as_mut_ptr() as *mut c_void, 1) {
        -1 => Err(OsError::last_os_error()),
        0 => Ok(()),
        _ => Err(OsError::new(ErrorKind::Other, "Read data when there should be nothing to read")),
    }
}

pub unsafe fn fd_close(fd: c_int) -> Result<(), OsError> {
    match close(fd) {
        -1 => Err(OsError::last_os_error()),
        _ => Ok(())
    }
}

pub enum ForkResult {
    Child,
    Parent {
        child_pid: pid_t
    },
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UserRegsAMD64 {
    pub r15: c_ulonglong,
    pub r14: c_ulonglong,
    pub r13: c_ulonglong,
    pub r12: c_ulonglong,
    pub rbp: c_ulonglong,
    pub rbx: c_ulonglong,
    pub r11: c_ulonglong,
    pub r10: c_ulonglong,
    pub r9: c_ulonglong,
    pub r8: c_ulonglong,
    pub rax: c_ulonglong,
    pub rcx: c_ulonglong,
    pub rdx: c_ulonglong,
    pub rsi: c_ulonglong,
    pub rdi: c_ulonglong,
    pub orig_rax: c_ulonglong,
    pub rip: c_ulonglong,
    pub cs: c_ulonglong,
    pub eflags: c_ulonglong,
    pub rsp: c_ulonglong,
    pub ss: c_ulonglong,
    pub fs_base: c_ulonglong,
    pub gs_base: c_ulonglong,
    pub ds: c_ulonglong,
    pub es: c_ulonglong,
    pub fs: c_ulonglong,
    pub gs: c_ulonglong,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UserRegsX86 {
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub eax: u32,
    pub xds: u32,
    pub xes: u32,
    pub xfs: u32,
    pub xgs: u32,
    pub orig_eax: u32,
    pub eip: u32,
    pub xcs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub xss: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union UserRegs {
    pub amd64: UserRegsAMD64,
    pub x86: UserRegsX86,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IOVec {
    iov_base: *mut c_void,
    iov_len: usize,
}

