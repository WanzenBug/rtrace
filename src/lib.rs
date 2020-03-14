pub use std::io::Error as OsError;
use std::os::raw::c_void;
use std::process::Command;

pub use crate::event::ProcessEvent;
pub use crate::process::StoppedProcess;
use crate::raw::{p_trace, process_sync, ProcessWait};

mod process;
mod event;
mod command_ext;
mod raw;

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

        let (ours, theirs) = process_sync()?;

        unsafe {
            let raw = theirs.into_raw_fd();
            self.pre_exec(move || {
                // NB: PTrace setup happens somewhere here
                let theirs = ProcessWait::from_raw_fd(raw);
                theirs.wait();
                Ok(())
            });
        }
        let child_pid = self.fork_and_exec()?;
        let options = libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEEXEC;

        unsafe {
            eprintln!("libc::PTRACE_SEIZE");
            p_trace(libc::PTRACE_SEIZE, child_pid, None, Some(options as *mut c_void))?;
            eprintln!("Done");
        }
        ours.resume();

        Ok(TracedChildTree {
            child: child_pid,
        })
    }
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
