pub use std::io::Error as OsError;
use std::io::ErrorKind;
use std::os::raw::c_void;
use std::process::Command;

use log::debug;
use log::trace;

pub use crate::event::ProcessEvent;
pub use crate::process::StoppedProcess;
use crate::raw::get_syscall_number;
use crate::raw::p_trace;
use crate::raw::pipe;
use crate::raw::fd_close;
use crate::raw::read_wait;
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
        use crate::command_ext::ForkAndExec;

        trace!("Called TracingCommand::spawn_with_tracing on {:?}", self);


        debug!("Setting pre_exec hook to wait for synchronization");
        let (ours, theirs) = unsafe {
            debug!("Creating process synchronization pipe");
            let (ours, theirs) = pipe()?;
            debug!("Creation successful");

            self.pre_exec(move || {
                // We need to close the write clone here
                fd_close(ours)?;

                // NB: PTrace setup happens somewhere here
                read_wait(theirs)?;
                fd_close(theirs)?;
                Ok(())
            });
            (ours, theirs)
        };

        debug!("Fork and execute child");
        let child_pid = self.fork_and_exec()?;
        debug!("Fork successful: child PID {}", child_pid);


        // NB: At this point, the read and in our process can be closed safely
        debug!("Closing read end of synchronization pipe in parent process");
        unsafe { fd_close(theirs) }?;
        debug!("Closing successful");

        let options = libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEEXEC;

        debug!("Calling PTRACE_SEIZE and PTRACE_INTERRUPT on child process");
        unsafe {
            p_trace(libc::PTRACE_SEIZE, child_pid, None, Some(options as *mut c_void))?;
            p_trace(libc::PTRACE_INTERRUPT, child_pid, None, None)?;
        }
        debug!("PTRACE_SEIZE and PTRACE_INTERRUPT successful");

        debug!("Closing synchronization pipe, child can continue to execute");
        unsafe { fd_close(ours) }?;
        debug!("Closing successful");

        debug!("Syncing up to child process via waitpid()");
        match WaitPID::from_process(child_pid)? {
            WaitPID::PTraceEvent { kind: PTraceEventKind::Stop, .. } => (),
            x => Err(OsError::new(ErrorKind::Other, format!("Expected PTRACE_EVENT_STOP, got {:?} instead", x)))?,
        }
        debug!("Restart until next syscall event");
        unsafe { p_trace(libc::PTRACE_SYSCALL, child_pid, None, None) }?;

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

        match get_syscall_number(child_pid)? {
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
    unsafe { p_trace(libc::PTRACE_SYSCALL, child_pid, None, None) }?;
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
