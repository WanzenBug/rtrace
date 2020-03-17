use std::collections::HashMap;
pub use std::io::Error as OsError;
use std::io::ErrorKind;
use std::process::Command;

use libc::pid_t;
use log::debug;
use log::trace;

pub use crate::event::ProcessEvent;
pub use crate::event::ProcessEventKind;
pub use crate::process::StoppedProcess;
use crate::raw::ChildState;
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
    _child: libc::pid_t,
    child_states: HashMap<pid_t, ChildState>,
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

        debug!("Syncing up to child process via waitpid()");
        match WaitPID::from_process(child_pid)? {
            WaitPID::PTraceEvent { kind: PTraceEventKind::Stop, .. } => (),
            x => Err(OsError::new(ErrorKind::Other, format!("Expected PTRACE_EVENT_STOP, got {:?} instead", x)))?,
        }

        debug!("Dropping child guard, child can continue to execute");
        drop(child_guard);
        debug!("Closing successful");

        debug!("Restart until next syscall event");
        p_trace_syscall(child_pid, None)?;


        // From the way we synchronize with the child process, the child process can be in 4
        // different locations:
        //
        // From childs pre_exec lambda in command_ext.rs:
        //    > // This is only executed in the child context. Close all unneeded file descriptors
        //    > fd_close(our_child_stop)?;
        //    > fd_close(our_parent_stop)?;
        //    >
        //    > // With this close, the parent can check that the child process has reached this
        //    > // execution point
        // 1|2> fd_close(their_parent_stop)?;
        //    >
        //    > // Wait for parent to close the other pipe. This signals the parent has done the
        //    > // preparatory work
        // 3|4> read_wait(their_child_stop)?;
        //    > fd_close(their_child_stop)?;
        // The child_guard ensures fd_close() was at least started, so the child can be in
        // the close syscall in enter or exit (1|2).
        // The other possibility is that the child stops at (3¼), which is the read() call, either
        // in enter or exit event.


        // Check for first read call
        loop {
            match next_syscall(child_pid)? {
                libc::SYS_read => {
                    debug!("Got expected read() call");
                    break;
                },
                libc::SYS_close => {
                    debug!("Got expected close() call");
                    continue
                },
                x => {
                    return Err(OsError::new(ErrorKind::Other, format!("Expected syscall to be read() or close(), got {} instead", x)));
                },
            }
        }

        // Now we have either observed the read() enter or exit event. The next event determines
        // our relative position in the child code

        debug!("This is either the read() exit or close() enter. With this call we should know if we started with a enter or exit event");
        let reached_close = match next_syscall(child_pid)? {
            libc::SYS_read => {
                debug!("Entered second read(), must be the exit call");
                false
            }
            libc::SYS_close => {
                debug!("Entered first close(), process almost synchronized!");
                true
            }
            x => Err(OsError::new(ErrorKind::Other, format!("Expected syscall to be read() exit or close() enter, got {} instead", x)))?,
        };

        if !reached_close {
            debug!("Not yet entered close(), it must be the next call");
            match next_syscall(child_pid)? {
                libc::SYS_close => debug!("Reached expected close() enter"),
                x => Err(OsError::new(ErrorKind::Other, format!("Expected syscall to be close() enter, got {} instead", x)))?,
            }
        }

        match next_syscall(child_pid)? {
            libc::SYS_close => debug!("Got SYS_close exit"),
            x => Err(OsError::new(ErrorKind::Other, format!("Expected syscall to be close() exit, got {} instead", x)))?,
        }

        debug!("All synced up, the next syscall events have to be 'enter' events");

        Ok(TracedChildTree {
            _child: child_pid,
            child_states: HashMap::new(),
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
        debug!("Trying to get next event from traced children");
        let wait_pid = WaitPID::from_all_children()?;
        trace!("Next event: {:?}", wait_pid);
        Ok(StoppedProcess::from_wait_pid(self, wait_pid))
    }
}

impl<F, R, E> Iterator for TracedChildTreeIter<F> where F: for<'r> FnMut(StoppedProcess<'r>) -> Result<Option<R>, E>, E: Into<OsError> {
    type Item = Result<R, OsError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            debug!("Waiting for next event");
            let proc = match self.tree.next_event() {
                Ok(proc) => proc,
                Err(ref e) if e.raw_os_error() == Some(libc::ECHILD) => return None,
                Err(e) => return Some(Err(e)),
            };
            trace!("Next stopped process: {:?}", proc);

            trace!("Will call user supplied action on stopped process");
            match (self.action)(proc) {
                Ok(Some(v)) => return Some(Ok(v)),
                Ok(None) => continue,
                Err(e) => return Some(Err(e.into())),
            }
        }
    }
}
