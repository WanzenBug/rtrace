pub use std::io::Error as OsError;
use std::io::ErrorKind;
use std::process::Command;

use log::debug;
use log::trace;

pub use crate::event::ProcessEvent;
pub use crate::process::StoppedProcess;
use crate::raw::get_syscall_number;
use crate::raw::p_trace_seize_and_interrupt;
use crate::raw::p_trace_syscall;
use crate::wait_pid::PTraceEventKind;
use crate::wait_pid::WaitPID;

mod process;
mod event;
mod command_ext;
mod raw;
mod wait_pid;

pub struct TracedChildTree {
    child: libc::pid_t,
}


pub struct TracedChildTreeIter<F> {
    tree: TracedChildTree,
    action: F,
}

pub trait TracingCommand {
    fn spawn_with_tracing(&mut self) -> Result<TracedChildTree, OsError>;
}

impl TracingCommand for Command {
    fn spawn_with_tracing(&mut self) -> Result<TracedChildTree, OsError> {
        use crate::command_ext::PreExecStopCommand;

        trace!("Called TracingCommand::spawn_with_tracing on {:?}", self);

        debug!("Fork and execute child");
        let child_guard = self.spawn_with_pre_exec_stop()?;
        let child_pid = child_guard.child_id();
        debug!("Fork successful: child PID {}", child_pid);

        p_trace_seize_and_interrupt(child_pid, libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEEXEC,
        )?;

        debug!("Dropping child guard, child can continue to execute");
        drop(child_guard);
        debug!("Closing successful");

        debug!("Syncing up to child process via waitpid()");
        match WaitPID::from_process(child_pid)? {
            WaitPID::PTraceEvent { kind: PTraceEventKind::Stop, .. } => (),
            x => Err(OsError::new(ErrorKind::Other, format!("Expected PTRACE_EVENT_STOP, got {:?} instead", x)))?,
        }
        debug!("Restart until next syscall event");
        p_trace_syscall(child_pid, None)?;

        debug!("This can either be the initial read() enter, or already the read() exit.");
        match next_syscall(child_pid)? {
            libc::SYS_read => debug!("Got expected SYS_read call"),
            x => Err(OsError::new(ErrorKind::Other, format!("Expected syscall to be SYS_read, got {} instead", x)))?,
        };

        debug!("This is either the SYS_read exit or SYS_close enter. With this call we should know if we started with a enter or exit event");
        let reached_close = match next_syscall(child_pid)? {
            libc::SYS_read => {
                debug!("Entered second SYS_read, must be the exit call");
                false
            }
            libc::SYS_close => {
                debug!("Entered first SYS_close, process almost syncronized!");
                true
            }
            x => Err(OsError::new(ErrorKind::Other, format!("Expected syscall to be SYS_read or SYS_close, got {} instead", x)))?,
        };

        if !reached_close {
            debug!("Not yet entered SYS_close, it must be the next call");
            match next_syscall(child_pid)? {
                libc::SYS_close => debug!("Reached expected SYS_close enter"),
                x => Err(OsError::new(ErrorKind::Other, format!("Expected syscall to be SYS_close, got {} instead", x)))?,
            }
        }

        match next_syscall(child_pid)? {
            libc::SYS_close => debug!("Got SYS_close exit"),
            x => Err(OsError::new(ErrorKind::Other, format!("Expected syscall to be SYS_close, got {} instead", x)))?,
        }

        debug!("All synced up, the next syscall events have to be ENTER events");

        Ok(TracedChildTree {
            child: child_pid,
        })
    }
}

fn next_syscall(child_pid: libc::pid_t) -> Result<i64, OsError> {
    match WaitPID::from_process(child_pid)? {
        WaitPID::SysCall { .. } => (),
        x => Err(OsError::new(ErrorKind::Other, format!("Expected syscall event, got {:?} instead", x)))?,
    }
    let number = get_syscall_number(child_pid)?;
    p_trace_syscall(child_pid, None)?;
    Ok(number)
}

pub trait TracedChildTreeExt {
    fn next_event(&mut self) -> Result<StoppedProcess, OsError>;
}

impl TracedChildTree {
    pub fn on_process_event<F, R, E>(self, action: F) -> TracedChildTreeIter<F> where F: for<'r> FnMut(StoppedProcess<'r>) -> Result<Option<R>, E>, E: Into<OsError> {
        TracedChildTreeIter {
            tree: self,
            action,
        }
    }
}

impl TracedChildTreeExt for TracedChildTree {
    fn next_event(&mut self) -> Result<StoppedProcess, OsError> {
        unimplemented!()
    }
}

impl<F, R, E> Iterator for TracedChildTreeIter<F> where F: for<'r> FnMut(StoppedProcess<'r>) -> Result<Option<R>, E>, E: Into<OsError> {
    type Item = Result<R, OsError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let proc = match self.tree.next_event() {
                Ok(proc) => proc,
                Err(e) => return Some(Err(e)),
            };

            match (self.action)(proc) {
                Ok(Some(v)) => return Some(Ok(v)),
                Ok(None) => continue,
                Err(e) => return Some(Err(e.into())),
            }
        }
    }
}
