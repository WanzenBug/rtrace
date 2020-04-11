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
use crate::raw::get_syscall_number;
use crate::raw::p_trace_become_tracer;
use crate::raw::p_trace_syscall;
use crate::raw::ChildState;
pub use crate::wait_pid::PTraceEventKind;
use crate::wait_pid::WaitPID;

mod command_ext;
pub mod enhanced_tracer;
mod event;
mod process;
mod raw;
mod wait_pid;

pub struct TracedChildTree {
    _child: libc::pid_t,
    child_states: HashMap<pid_t, ChildState>,
}

pub struct TracedChildTreeIter<H> {
    tree: TracedChildTree,
    handler: H,
}

pub trait TracingCommand {
    fn spawn_with_tracing(&mut self) -> Result<TracedChildTree, OsError>;
}

pub trait RawTraceEventHandler {
    type IterationItem;
    type Error: From<OsError>;

    fn handle(
        &mut self,
        stop_event: StoppedProcess,
    ) -> Result<Option<Self::IterationItem>, Self::Error>;
}

impl<F, E, R> RawTraceEventHandler for F
where
    F: FnMut(StoppedProcess) -> Result<Option<R>, E>,
    E: From<OsError>,
{
    type IterationItem = R;
    type Error = E;

    fn handle(
        &mut self,
        stop_event: StoppedProcess,
    ) -> Result<Option<Self::IterationItem>, Self::Error> {
        (self)(stop_event)
    }
}

impl TracingCommand for Command {
    fn spawn_with_tracing(&mut self) -> Result<TracedChildTree, OsError> {
        use crate::command_ext::PreExecStopCommand;

        trace!("Called TracingCommand::spawn_with_tracing on {:?}", self);

        debug!("Fork and execute child");
        let child_guard = self.spawn_with_pre_exec_stop()?;
        let child_pid = child_guard.child_id();
        debug!("Fork successful: child PID {}", child_pid);

        p_trace_become_tracer(child_pid)?;

        debug!("Restart until next syscall event");
        p_trace_syscall(child_pid, None)?;

        debug!("Dropping child guard, child can continue to execute");
        drop(child_guard);
        debug!("Closing successful");

        // From the way we synchronize with the child process, the child process can be in 4
        // different locations:
        //
        // From children pre_exec lambda in command_ext.rs:
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
        //    > // NB: we need a second wait here, because PTRACE_ATTACH will skip the read() exit
        //    > // of the first call.
        // 5  > read_wait(their_child_stop)?;
        //    > fd_close(their_child_stop)?;
        // The child_guard ensures fd_close() was at least started, so the child can be in
        // the close syscall in enter or exit (1|2).
        // Another possibility is that the child stops at (3/4), which is the read() call, either
        // in enter or exit event.
        // The last possibility is that we used PTRACE_ATTACH, which will skip exit events of
        // in-progress system calls.

        // Observe all close() system calls (possibility 1/2) until a read() is encountered
        loop {
            match next_syscall(child_pid)? {
                libc::SYS_read => {
                    debug!("Got expected read() call");
                    break;
                }
                libc::SYS_close => {
                    debug!("Got expected close() call");
                    debug!("Continuing until read() call is observed");
                    continue;
                }
                x => {
                    return Err(OsError::new(
                        ErrorKind::Other,
                        format!(
                            "Expected syscall to be read() or close(), got {} instead",
                            x
                        ),
                    ));
                }
            }
        }

        // Now we have either observed the read() enter or exit event (possibility 3,4,5). We again
        // just observe all read() calls until a close() is encountered. Then we are all synced up
        loop {
            match next_syscall(child_pid)? {
                libc::SYS_close => {
                    debug!("Got expected close() call");
                    debug!("All synced up to child process");
                    break;
                }
                libc::SYS_read => {
                    debug!("Got expected read() call");
                    debug!("Continuing until close() call is observed");
                    continue;
                }
                x => {
                    return Err(OsError::new(
                        ErrorKind::Other,
                        format!(
                            "Expected syscall to be read() or close(), got {} instead",
                            x
                        ),
                    ));
                }
            }
        }

        match next_syscall(child_pid)? {
            libc::SYS_close => debug!("Got SYS_close exit"),
            x => {
                return Err(OsError::new(
                    ErrorKind::Other,
                    format!("Expected syscall to be close() exit, got {} instead", x),
                ))
            }
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
        x => {
            return Err(OsError::new(
                ErrorKind::Other,
                format!("Expected syscall event, got {:?} instead", x),
            ))
        }
    }
    let number = get_syscall_number(child_pid)?;
    p_trace_syscall(child_pid, None)?;
    Ok(number)
}

impl TracedChildTree {
    pub fn on_process_event<H>(self, handler: H) -> TracedChildTreeIter<H> {
        TracedChildTreeIter {
            tree: self,
            handler,
        }
    }

    fn next_event(&mut self) -> Result<StoppedProcess, OsError> {
        debug!("Trying to get next event from traced children");
        let wait_pid = WaitPID::from_all_children()?;
        trace!("Next event: {:?}", wait_pid);
        Ok(StoppedProcess::from_wait_pid(self, wait_pid))
    }
}

impl<H> Iterator for TracedChildTreeIter<H>
where
    H: RawTraceEventHandler,
{
    type Item = Result<H::IterationItem, H::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            debug!("Waiting for next event");
            let proc = match self.tree.next_event() {
                Ok(proc) => proc,
                Err(ref e) if e.raw_os_error() == Some(libc::ECHILD) => return None,
                Err(e) => return Some(Err(e.into())),
            };
            trace!("Next stopped process: {:?}", proc);

            trace!("Will call user supplied action on stopped process");
            match self.handler.handle(proc) {
                Ok(Some(v)) => return Some(Ok(v)),
                Ok(None) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
    }
}
