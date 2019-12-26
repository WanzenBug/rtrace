use std::ffi::{CStr, CString};
use std::io::ErrorKind;
use std::process;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod bindings;

mod raw;

const MAX_FILE_PATH_LENGTH: usize = 4096;

pub(crate) type Error = Box<dyn std::error::Error + 'static>;
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[must_use = "Traced child process cannot will not continue with monitoring"]
#[derive(Debug)]
pub struct TraceableChild {
    handle: process::Child,
}

pub trait TraceableCommand {
    fn spawn_traced(&mut self) -> Result<TraceableChild>;
}

impl TraceableCommand for std::process::Command {
    fn spawn_traced(&mut self) -> Result<TraceableChild> {
        use std::os::unix::process::CommandExt;

        let cmd = unsafe {
            self.pre_exec(|| {
                raw::ptrace::trace_me().expect("trace_me() cannot fail");
                Ok(())
            })
        };
        let child = cmd.spawn()?;
        let pid = child.id() as raw::ptrace::PTracePID;

        raw::ptrace::wait_for(pid)?;
        raw::ptrace::set_trace_syscall_option(pid)?;
        raw::ptrace::trace_syscall(pid)?;

        Ok(
            TraceableChild {
                handle: child,
            }
        )
    }
}

impl TraceableChild {
    pub fn detach(self) -> Result<process::Child> {
        raw::ptrace::detach(self.handle.id() as raw::ptrace::PTracePID)?;
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
    SyscallUnknown(u8),
    ExitNormally(i32),
    ExitSignal(i32),
}

impl Fingerprint {
    pub fn resume(&mut self) -> Result<()> {
        if self.state != TraceeState::Stopped {
            return Ok(());
        }

        raw::ptrace::trace_syscall(self.pid)?;
        self.state = TraceeState::Resumed;
        Ok(())
    }

    pub fn read_c_str(&mut self, base_address: u64) -> Result<CString> {
        if self.state != TraceeState::Stopped {
            Err(std::io::Error::from(ErrorKind::PermissionDenied))?;
        }
        let mut buf = [0; MAX_FILE_PATH_LENGTH];
        raw::ptrace::read_from_process(self.pid, &mut buf, base_address)?;
        let first_null = buf[..].iter()
            .position(|&x| x == b'\0')
            .ok_or_else(|| format!("Could not find CString in process {} at address {:x}", self.pid, base_address))?;
        let string = CString::from(CStr::from_bytes_with_nul(&buf[..first_null + 1])?);
        Ok(string)
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
    type Item = Result<Fingerprint>;

    fn next(&mut self) -> Option<Self::Item> {
        let pid = loop {
            use raw::ptrace::WaitPID::*;
            match raw::ptrace::wait_all() {
                Ok(NoChild) => return None,
                Ok(Exited { pid, exit_status }) => return Some(Ok(Fingerprint {
                    pid,
                    event: FingerprintEvent::ExitNormally(exit_status),
                    state: TraceeState::Exited,
                })),
                Ok(Terminated { pid, termination_signal }) => return Some(Ok(Fingerprint {
                    pid,
                    event: FingerprintEvent::ExitSignal(termination_signal),
                    state: TraceeState::Exited,
                })),
                Ok(SysCall { pid }) => break pid,
                Err(e) => return Some(Err(e)),
            };
        };

        let event = match get_syscall_event(pid) {
            Ok(e) => e,
            Err(e) => return Some(Err(e)),
        };
        return Some(Ok(Fingerprint {
            pid,
            event,
            state: TraceeState::Stopped,
        }));
    }
}


fn get_syscall_event(pid: raw::ptrace::PTracePID) -> Result<FingerprintEvent> {
    use raw::ptrace::{PtraceSyscallInfo, PtraceSyscallEventArgs};


    unsafe {
        match raw::ptrace::get_syscall_info(pid)? {
            PtraceSyscallInfo { op: 0, .. } => Err(format!("Process {} not stopped because of syscall event", pid).into()),
            PtraceSyscallInfo { op: 1, event_args: PtraceSyscallEventArgs { entry }, .. } => {
                Ok(FingerprintEvent::SyscallEnter {
                    syscall_number: entry.nr,
                    args: entry.args,
                })
            }
            PtraceSyscallInfo { op: 2, event_args: PtraceSyscallEventArgs { exit }, .. } => {
                Ok(FingerprintEvent::SyscallExit {
                    return_val: exit.rval,
                    is_error: exit.is_error != 0,
                })
            }
            PtraceSyscallInfo { op: 3, .. } => Err("Got seccomp stop".into()),
            PtraceSyscallInfo { op, .. } => Ok(FingerprintEvent::SyscallUnknown(op))
        }
    }
}
