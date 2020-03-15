use std::os::unix::process::CommandExt;
use std::process::Command;

use libc::pid_t;

use crate::OsError;
use crate::raw::fork;
use crate::raw::ForkResult;

pub trait ForkAndExec: CommandExt {
    fn fork_and_exec(&mut self) -> Result<pid_t, OsError>;

    unsafe fn pre_exec<F>(&mut self, f: F) -> &mut Self where F: FnMut() -> Result<(), OsError> + Send + Sync + 'static;
}

impl ForkAndExec for Command {
    fn fork_and_exec(&mut self) -> Result<pid_t, OsError> {
        unsafe {
            match fork()? {
                ForkResult::Child => {
                    let err = self.exec();
                    panic!("Error in fork: {}", err);
                }
                ForkResult::Parent { child_pid } => Ok(child_pid)
            }
        }
    }

    unsafe fn pre_exec<F>(&mut self, f: F) -> &mut Self where F: FnMut() -> Result<(), OsError> + Send + Sync + 'static {
        CommandExt::pre_exec(self, f)
    }
}
