use std::ffi::{CStr, CString};
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_long, c_longlong, c_ulong, c_void};
use std::process;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod bindings;

const MAX_FILE_PATH_LENGTH: usize = 4096;

#[repr(C)]
#[derive(Debug)]
struct WaitPID {
    pid: bindings::__pid_t,
    exited: c_char,
    exit_status: c_int,
    terminated_by_signal: c_char,
    termination_signal: c_int,
    is_stopped: c_char,
    syscalled: c_char,
    no_child: c_char,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PtraceSyscallInfoEntry {
    nr: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PtraceSyscallInfoExit {
    rval: i64,
    is_error: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PtraceSyscallInfoSeccomp {
    nr: u64,
    args: [u64; 6],
    ret_data: u32,
}

#[repr(C)]
union PtraceSyscallEventArgs {
    entry: PtraceSyscallInfoEntry,
    exit: PtraceSyscallInfoExit,
    seccomp: PtraceSyscallInfoSeccomp,
}

#[repr(C)]
struct PtraceSyscallInfo {
    op: u8,
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    event_args: PtraceSyscallEventArgs,
}

extern "C" {
    #[must_use]
    fn wrapped_fixed_arg_ptrace(request: bindings::__ptrace_request, pid: bindings::__pid_t, addr: *mut c_void, data: *mut c_void) -> c_long;

    #[must_use]
    fn wrapped_waitpid(pid: bindings::__pid_t, options: c_int) -> WaitPID;

    #[must_use]
    fn wrapped_process_vm_readv_string(pid: bindings::__pid_t, dest: *mut c_char, length: bindings::__ssize_t, source: bindings::__uint64_t) -> bindings::__ssize_t;

    fn stop_self();
}

#[must_use = "Traced child process cannot will not continue with monitoring"]
#[derive(Debug)]
pub struct TraceableChild {
    handle: process::Child,
}

pub trait TraceableCommand {
    fn spawn_traced(&mut self) -> Result<TraceableChild, std::io::Error>;
}

impl TraceableCommand for std::process::Command {
    fn spawn_traced(&mut self) -> Result<TraceableChild, std::io::Error> {
        use std::os::unix::process::CommandExt;

        let cmd = unsafe {
            self.pre_exec(|| {
                let ret = wrapped_fixed_arg_ptrace(bindings::__ptrace_request_PTRACE_TRACEME, 0, std::ptr::null_mut(), std::ptr::null_mut());
                if ret == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
        };
        let child = cmd.spawn()?;
        let pid = child.id() as bindings::__pid_t;

        let ret = unsafe {
            wrapped_waitpid(pid, 0)
        };
        if ret.pid == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if ret.is_stopped != 1 {
            return Err(std::io::Error::from(ErrorKind::Other));
        }

        let ret = unsafe {
            wrapped_fixed_arg_ptrace(bindings::__ptrace_request_PTRACE_SETOPTIONS, pid, std::ptr::null_mut(), bindings::__ptrace_setoptions_PTRACE_O_TRACESYSGOOD as *mut c_void)
        };
        if ret == -1 {
            return Err(std::io::Error::last_os_error());
        }

        let ret = unsafe {
            wrapped_fixed_arg_ptrace(bindings::__ptrace_request_PTRACE_SYSCALL, pid, std::ptr::null_mut(), std::ptr::null_mut())
        };
        if ret == -1 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(
            TraceableChild {
                handle: child,
            }
        )
    }
}

impl TraceableChild {
    pub fn detach(self) -> Result<process::Child, std::io::Error> {
        unsafe {
            wrapped_fixed_arg_ptrace(bindings::__ptrace_request_PTRACE_DETACH, self.handle.id() as bindings::__pid_t, std::ptr::null_mut(), std::ptr::null_mut())
        };
        Ok(self.handle)
    }

    pub fn stdin(&mut self) -> Option<&mut process::ChildStdin> {
        self.handle.stdin.as_mut()
    }

    pub fn stdout(&mut self) -> Option<&mut process::ChildStdout> {
        self.handle.stdout.as_mut()
    }

    pub fn stderr(&mut self) -> Option<&mut process::ChildStderr> {
        self.handle.stderr.as_mut()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TraceeState {
    Stopped,
    Exited,
    Resumed,
}

#[must_use]
#[derive(Debug)]
pub struct Fingerprint {
    pid: i32,
    event: FingerprintEvent,
    state: TraceeState,
}

#[derive(Debug, Copy, Clone)]
pub enum FingerprintEvent {
    SyscallEnter {
        syscall_number: u64,
        args: [u64; 6],
    },
    SyscallExit {
        return_val: i64,
        is_error: bool,
    },
    SyscallUnknown,
    ExitNormally(i32),
    ExitSignal(i32),
}

impl Fingerprint {
    pub fn resume(&mut self) -> Result<(), std::io::Error> {
        if self.state != TraceeState::Stopped {
            return Ok(());
        }

        let ret = unsafe {
            wrapped_fixed_arg_ptrace(bindings::__ptrace_request_PTRACE_SYSCALL, self.pid, std::ptr::null_mut(), std::ptr::null_mut())
        };
        if ret == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            self.state = TraceeState::Resumed;
            Ok(())
        }
    }

    pub fn read_c_str(&mut self, base_address: u64) -> Result<CString, std::io::Error> {
        if self.state != TraceeState::Stopped {
            Err(ErrorKind::PermissionDenied)?;
        }

        let mut buf: MaybeUninit<[u8; MAX_FILE_PATH_LENGTH]> = MaybeUninit::uninit();

        let ret = unsafe {
            wrapped_process_vm_readv_string(self.pid, buf.as_mut_ptr() as *mut i8, MAX_FILE_PATH_LENGTH as i64, base_address as u64)
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let buf = unsafe {
            buf.assume_init()
        };

        let cstr = match CStr::from_bytes_with_nul(&buf[..=ret as usize]) {
            Ok(v) => v,
            Err(_) => Err(ErrorKind::InvalidData)?,
        };
        Ok(CString::from(cstr))
    }

    pub fn event(&self) -> FingerprintEvent {
        self.event
    }
}

impl Drop for Fingerprint {
    fn drop(&mut self) {
        let _ = self.resume();
    }
}

impl Iterator for TraceableChild {
    type Item = Result<Fingerprint, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let x = loop {
            let wait_result = unsafe {
                wrapped_waitpid(-1, 0x40000000)
            };
            match wait_result {
                WaitPID { pid: -1, no_child: 1, .. } => return None,
                WaitPID { pid: -1, .. } => return Some(Err(std::io::Error::last_os_error())),
                WaitPID { exited: 1, exit_status, pid, .. } => return Some(Ok(Fingerprint {
                    pid,
                    event: FingerprintEvent::ExitNormally(exit_status),
                    state: TraceeState::Exited,
                })),
                WaitPID { terminated_by_signal: 1, termination_signal, pid, .. } => return Some(Ok(Fingerprint {
                    pid,
                    event: FingerprintEvent::ExitSignal(termination_signal),
                    state: TraceeState::Exited,
                })),
                x => break x,
            };
        };

        let ev = match get_syscall_event(x.pid) {
            Ok(e) => e,
            Err(e) => return Some(Err(e)),
        };
        return Some(Ok(Fingerprint {
            pid: x.pid,
            event: ev,
            state: TraceeState::Stopped,
        }));
    }
}


fn get_syscall_event(pid: bindings::__pid_t) -> Result<FingerprintEvent, std::io::Error> {
    let mut info = MaybeUninit::<PtraceSyscallInfo>::uninit();
    let size = std::mem::size_of_val(&info);
    let ret = unsafe {
        wrapped_fixed_arg_ptrace(0x420e, pid, size as *mut c_void, info.as_mut_ptr() as *mut c_void)
    };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    let ev = unsafe {
        match info {
            PtraceSyscallInfo { op: 1, event_args: PtraceSyscallEventArgs { entry }, .. } => {
                FingerprintEvent::SyscallEnter {
                    syscall_number: entry.nr,
                    args: entry.args,
                }
            }
            PtraceSyscallInfo { op: 2, event_args: PtraceSyscallEventArgs { exit }, .. } => {
                FingerprintEvent::SyscallExit {
                    return_val: exit.rval,
                    is_error: exit.is_error != 0,
                }
            }
            PtraceSyscallInfo { op, .. } => {
                eprintln!("Unknown op {}", op);
                FingerprintEvent::SyscallUnknown
            }
        }
    };

    Ok(ev)
}
