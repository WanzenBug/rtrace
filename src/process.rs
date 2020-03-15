use std::os::raw::c_int;
use std::os::raw::c_void;

use libc::pid_t;

use crate::{OsError, raw};
use crate::ProcessEvent;
use crate::TracedChildTree;

#[derive(Clone)]
pub struct StoppedProcess<'a> {
    pub pid: pid_t,
    pending_signal: Option<c_int>,
    pub state: StoppedProcessState,
    tracer: &'a TracedChildTree,
}

#[derive(Debug, Copy, Clone)]
pub enum StoppedProcessState {
    PTraceStop,
    Ignored,
    Exited,
    Resumed,
}

impl<'a> StoppedProcess<'a> {
    pub fn id(&self) -> i32 {
        self.pid
    }

    pub fn exited(&self) -> bool {
        match self.state {
            StoppedProcessState::Exited => true,
            _ => false,
        }
    }

    pub fn event(&self) -> Result<ProcessEvent, OsError> {
        unimplemented!()
    }

    pub fn detach(mut self) -> Result<(), OsError> {
        unsafe {
            raw::p_trace(libc::PTRACE_DETACH, self.pid, None, None)
        }?;

        self.state = StoppedProcessState::Exited;
        Ok(())
    }

    pub fn ignore(mut self) -> Result<(), OsError> {
        self.state = StoppedProcessState::Ignored;
        Ok(())
    }

    pub fn resume_with_syscall(mut self) -> Result<(), OsError> {
        unsafe {
            raw::p_trace(libc::PTRACE_SYSCALL, self.pid, None, self.pending_signal.map(|s| s as *mut c_void))
        }?;

        self.state = StoppedProcessState::Resumed;
        Ok(())
    }

    pub fn resume(mut self) -> Result<(), OsError> {
        unsafe {
            raw::p_trace(libc::PTRACE_CONT, self.pid, None, self.pending_signal.map(|s| s as *mut c_void))
        }?;

        self.state = StoppedProcessState::Resumed;
        Ok(())
    }
}

impl<'a> Drop for StoppedProcess<'a> {
    fn drop(&mut self) {
        let this = std::mem::replace(self, StoppedProcess { pid: self.pid, pending_signal: None, state: StoppedProcessState::Ignored, tracer: self.tracer });
        match this.state {
            StoppedProcessState::PTraceStop => {
                let _ = this.detach();
            }
            _ => (),
        }
    }
}
