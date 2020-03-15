use std::io::ErrorKind;
use std::os::raw::c_int;
use std::os::raw::c_ulong;
use libc::pid_t;

use crate::OsError;
use crate::raw::p_trace_get_event_message;
use crate::raw::wait_pid;

#[derive(Debug)]
pub enum WaitPID {
    Exited {
        pid: pid_t,
        exit_status: i32,
    },
    Terminated {
        pid: pid_t,
        termination_signal: i32,
    },
    SysCall {
        pid: pid_t,
    },
    PTraceEvent {
        pid: pid_t,
        message: c_ulong,
        kind: PTraceEventKind,
    },
    Signal {
        pid: pid_t,
        signal: i32,
    },
}

#[derive(Debug, Copy, Clone)]
pub enum PTraceEventKind {
    Exit,
    Fork,
    VFork,
    VForkDone,
    Clone,
    Exec,
    Stop,
}


impl WaitPID {
    pub fn from_process(pid: pid_t) -> Result<WaitPID, OsError> {
        let (w_pid, status) = wait_pid(pid, 0)?;
        assert_eq!(w_pid, pid);
        WaitPID::from_status(w_pid, WaitPIDStatus(status))
    }

    pub fn from_all_children() -> Result<WaitPID, OsError> {
        let (w_pid, status) = wait_pid(-1, libc::__WALL)?;
        WaitPID::from_status(w_pid, WaitPIDStatus(status))
    }

    fn from_status(source_pid: pid_t, status: WaitPIDStatus) -> Result<WaitPID, OsError> {
        if status.exited() {
            return Ok(WaitPID::Exited {
                pid: source_pid,
                exit_status: status.exit_status(),
            });
        }

        assert!(status.stopped(), "Received waitpid() status that is neither WIFEXITED() nor WIFSTOPPED()!");

        if status.signaled() {
            return Ok(WaitPID::Terminated {
                pid: source_pid,
                termination_signal: status.termination_signal(),
            });
        }

        if status.syscalled() {
            return Ok(WaitPID::SysCall {
                pid: source_pid,
            });
        }
        let event_kind = match status.ptrace_event() {
            0 => return Ok(WaitPID::Signal {
                pid: source_pid,
                signal: status.stop_signal(),
            }),
            libc::PTRACE_EVENT_EXEC => PTraceEventKind::Exec,
            libc::PTRACE_EVENT_EXIT => PTraceEventKind::Exit,
            libc::PTRACE_EVENT_FORK => PTraceEventKind::Fork,
            libc::PTRACE_EVENT_VFORK => PTraceEventKind::VFork,
            libc::PTRACE_EVENT_VFORK_DONE => PTraceEventKind::VForkDone,
            libc::PTRACE_EVENT_CLONE => PTraceEventKind::Clone,
            // NB: not exported by libc right now
            128 => PTraceEventKind::Stop,
            x => return Err(OsError::new(ErrorKind::Other, format!("Unknown ptrace event status: {}", x))),
        };

        let msg = p_trace_get_event_message(source_pid)?;

        return Ok(WaitPID::PTraceEvent {
            pid: source_pid,
            message: msg,
            kind: event_kind,
        });
    }
}

#[derive(Debug, Copy, Clone)]
struct WaitPIDStatus(c_int);

impl WaitPIDStatus {
    fn exited(&self) -> bool {
        unsafe { libc::WIFEXITED(self.0) }
    }

    fn exit_status(&self) -> i32 {
        unsafe { libc::WEXITSTATUS(self.0) }
    }

    fn signaled(&self) -> bool {
        unsafe { libc::WIFSIGNALED(self.0) }
    }

    fn termination_signal(&self) -> i32 {
        unsafe { libc::WTERMSIG(self.0) }
    }

    fn stopped(&self) -> bool {
        unsafe { libc::WIFSTOPPED(self.0) }
    }

    fn stop_signal(&self) -> i32 {
        unsafe { libc::WSTOPSIG(self.0) }
    }

    fn syscalled(&self) -> bool {
        unsafe { libc::WSTOPSIG(self.0) == (libc::SIGTRAP | 0x80) }
    }

    fn ptrace_event(&self) -> i32 {
        self.0 >> 16
    }
}
