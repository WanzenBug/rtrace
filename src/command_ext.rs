use std::os::raw::c_int;
use std::os::unix::process::CommandExt;
use std::process::Command;

use libc::pid_t;
use log::debug;

use crate::OsError;
use crate::raw::fd_close;
use crate::raw::fork;
use crate::raw::ForkResult;
use crate::raw::pipe;
use crate::raw::read_wait;

#[derive(Debug)]
pub struct WaitingChildGuard {
    child_pid: pid_t,
    child_stop_fd: c_int,
}

pub trait PreExecStopCommand: CommandExt {
    fn spawn_with_pre_exec_stop(&mut self) -> Result<WaitingChildGuard, OsError>;

    unsafe fn pre_exec<F>(&mut self, f: F) -> &mut Self where F: FnMut() -> Result<(), OsError> + Send + Sync + 'static;
}

impl PreExecStopCommand for Command {
    fn spawn_with_pre_exec_stop(&mut self) -> Result<WaitingChildGuard, OsError> {
        unsafe {
            debug!("Creating child stop pipe");
            let (our_child_stop, their_child_stop) = pipe()?;
            debug!("Creation successful");

            debug!("Creating parent stop pipe");
            let (their_parent_stop, our_parent_stop) = pipe()?;
            debug!("Creation successful");

            debug!("Setting pre_exec hook to wait for synchronization");
            CommandExt::pre_exec(self, move || {
                // This is only executed in the child context. Close all unneeded file descriptors
                fd_close(our_child_stop)?;
                fd_close(our_parent_stop)?;

                // With this close, the parent can check that the child process has reached this
                // execution point
                fd_close(their_parent_stop)?;

                // Wait for parent to close the other pipe. This signals the parent has done the
                // preparatory work
                read_wait(their_child_stop)?;
                // NB: we need a second wait here, because PTRACE_ATTACH will skip the read() exit
                // of the first call.
                read_wait(their_child_stop)?;
                fd_close(their_child_stop)?;

                Ok(())
            });


            let child_pid = match fork()? {
                ForkResult::Child => {
                    let err = self.exec();
                    panic!("Error in fork: {}", err);
                }
                ForkResult::Parent { child_pid } => child_pid
            };
            debug!("Process forked, child pid: {}", child_pid);

            // After fork, we only execute in the parent process. Close all child file descriptors
            debug!("Closing child process' end of file descriptors");
            fd_close(their_child_stop)?;
            fd_close(their_parent_stop)?;

            // Wait for child to reach the pre_exec lambda. This can be checked by waiting on the
            // parent_stop pipe to close
            debug!("Waiting for child to reach synchronization point");
            read_wait(our_parent_stop)?;
            fd_close(our_parent_stop)?;

            debug!("Child ready to be configured");
            Ok(WaitingChildGuard {
                child_pid,
                child_stop_fd: our_child_stop,
            })
        }
    }

    unsafe fn pre_exec<F>(&mut self, f: F) -> &mut Self where F: FnMut() -> Result<(), OsError> + Send + Sync + 'static {
        CommandExt::pre_exec(self, f)
    }
}

impl WaitingChildGuard {
    pub fn child_id(&self) -> pid_t {
        self.child_pid
    }
}

impl Drop for WaitingChildGuard {
    fn drop(&mut self) {
        let _ = unsafe { fd_close(self.child_stop_fd) };
    }
}
