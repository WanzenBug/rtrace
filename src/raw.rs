use std::io::ErrorKind;
use std::os::raw::c_int;
use std::os::raw::c_long;
use std::os::raw::c_void;
use std::ptr::null_mut;

use libc::close;
use libc::pid_t;
use libc::pipe;
use libc::ptrace;
use libc::read;
use libc::waitpid;

use crate::OsError;
use std::mem::forget;

pub type PTraceRequest = libc::c_uint;

pub unsafe fn wait_pid(pid: pid_t, options: c_int) -> Result<(pid_t, c_int), OsError> {
    let mut status = 0;

    match waitpid(pid, &mut status as *mut c_int, options) {
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

pub enum ForkResult {
    Child,
    Parent {
        child_pid: pid_t
    },
}

pub unsafe fn fork() -> Result<ForkResult, OsError> {
    match libc::fork() {
        -1 => Err(OsError::last_os_error()),
        0 => Ok(ForkResult::Child),
        child_pid => Ok(ForkResult::Parent { child_pid })
    }
}

pub struct ProcessWait(c_int);

pub struct ProcessResume(c_int);

pub fn process_sync() -> Result<(ProcessResume, ProcessWait), OsError> {
    let mut result = [0, 0];
    match unsafe { pipe(result.as_mut_ptr()) } {
        -1 => Err(OsError::last_os_error()),
        // index 0 is the read end, 1 is the write end
        _ => Ok((ProcessResume(result[1]), ProcessWait(result[0])))
    }
}

impl ProcessWait {
    pub fn wait(self) -> Result<(), OsError> {
        let mut buf = [0u8];
        match unsafe { read(self.0, buf.as_mut_ptr() as *mut c_void, 1) } {
            -1 => Err(OsError::last_os_error()),
            0 => Ok(()),
            _ => Err(OsError::new(ErrorKind::InvalidData, "This pipe should never contain data")),
        }
    }

    pub unsafe fn into_raw_fd(self) -> c_int {
        let fd = self.0;
        forget(self);
        fd
    }

    pub unsafe fn from_raw_fd(fd: c_int) -> Self {
        ProcessWait(fd)
    }
}

impl ProcessResume {
    pub fn resume(self) {}
}

impl Drop for ProcessResume {
    fn drop(&mut self) {
        unsafe { close(self.0) };
    }
}

impl Drop for ProcessWait {
    fn drop(&mut self) {
        unsafe { close(self.0) };
    }
}
