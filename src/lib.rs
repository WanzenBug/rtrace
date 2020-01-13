use std::{
    ffi::{OsStr, OsString},
    io::ErrorKind,
    process,
};

pub mod fs;
pub mod paths;
pub mod util;

mod raw;

const MAX_FILE_PATH_LENGTH: usize = 4096;

pub type Error = Box<dyn std::error::Error + 'static>;
pub type Result<T> = std::result::Result<T, Error>;

#[must_use = "Traced child process cannot will not continue with monitoring"]
#[derive(Debug)]
pub struct TraceableChild {
    handle: (),
}

pub trait TraceableCommand {
    fn spawn_traced(self) -> Result<TraceableChild>;
}

impl TraceableCommand for process::Command {
    fn spawn_traced(mut self) -> Result<TraceableChild> {
        use std::os::unix::process::CommandExt;
        use std::sync::Barrier;
        use std::sync::Arc;

        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = barrier.clone();
        unsafe {
            self.pre_exec(move || {
                raw::ptrace::trace_me().expect("trace_me() cannot fail");
                barrier_clone.wait();
                raw::stop_self().expect("stop_self() cannot fail");
                Ok(())
            })
        };
        std::thread::spawn(move || {
            self.exec()
        });
        barrier.wait();
        let wait = raw::ptrace::wait_for(-1)?;
        let pid = match wait {
            // SIGSTOP == 19 (on x86_64)
            raw::ptrace::WaitPID::Signal { pid, signal: 19 } => pid,
            x => Err(format!("Expected SIGSTOP in child process, got {:?} instead", x))?,
        };
        raw::ptrace::set_trace_syscall_option(pid)?;
        raw::ptrace::trace_syscall_with_signal_delivery(pid, 0)?;

        Ok(
            TraceableChild {
                handle: (),
            }
        )
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
    Event {
        event_pid: u32,
        ty: raw::ptrace::PtraceEventTy,
    },
    SignalDelivery {
        signal: i32,
    },
    ExitNormally(i32),
    ExitSignal(i32),
}

impl Fingerprint {
    pub fn resume(&mut self) -> Result<()> {
        if self.state != TraceeState::Stopped {
            return Ok(());
        }
        let signal = match self.event {
            FingerprintEvent::SignalDelivery { signal } => signal,
            _ => 0,
        };
        raw::ptrace::trace_syscall_with_signal_delivery(self.pid, signal)?;
        self.state = TraceeState::Resumed;
        Ok(())
    }

    pub fn read_os_string(&mut self, base_address: u64) -> Result<OsString> {
        if self.state != TraceeState::Stopped {
            Err(std::io::Error::from(ErrorKind::PermissionDenied))?;
        }
        let mut buf = [0; MAX_FILE_PATH_LENGTH];
        raw::ptrace::read_from_process(self.pid, &mut buf, base_address)?;
        let first_null = buf[..].iter()
            .position(|&x| x == b'\0')
            .ok_or_else(|| format!("Could not find CString in process {} at address {:x}", self.pid, base_address))?;

        use std::os::unix::ffi::OsStrExt;
        Ok(OsStr::from_bytes(&buf[..first_null]).to_os_string())
    }

    pub fn event(&self) -> FingerprintEvent {
        self.event
    }

    pub fn pid(&self) -> u32 {
        self.pid as u32
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
        loop {
            use raw::ptrace::WaitPID::*;
            match raw::ptrace::wait_all() {
                Ok(SysCall { pid }) => {
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
                Ok(Signal { pid, signal }) => return Some(Ok(Fingerprint {
                    pid,
                    event: FingerprintEvent::SignalDelivery {
                        signal,
                    },
                    state: TraceeState::Stopped,
                })),
                Ok(PTraceEvent { pid, other_pid, ty }) => {
                    return Some(Ok(Fingerprint {
                        pid,
                        event: FingerprintEvent::Event {
                            event_pid: other_pid as u32,
                            ty,
                        },
                        state: TraceeState::Stopped,
                    }));
                }
                Err(e) => return Some(Err(e)),
            };
        };
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
            PtraceSyscallInfo { op: 3, .. } => Err("Got seccomp stop")?,
            PtraceSyscallInfo { op, .. } => Err(format!("Got unknown stop {}", op))?
        }
    }
}
