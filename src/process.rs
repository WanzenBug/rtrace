use std::fmt::Debug;
use std::fmt::Formatter;
use std::os::raw::{c_int, c_void};

use crate::event::ProcessEventKind;
use crate::OsError;
use crate::ProcessEvent;
use crate::raw::{ChildState, safe_process_vm_readv};
use crate::raw::get_syscall_event_legacy;
use crate::raw::p_trace_cont;
use crate::raw::p_trace_detach;
use crate::raw::p_trace_syscall;
use crate::TracedChildTree;
use crate::wait_pid::WaitPID;
use std::ffi::{OsString, OsStr};

pub struct StoppedProcess<'a> {
    state: StoppedProcessState,
    wait_pid: WaitPID,
    tracer: &'a mut TracedChildTree,
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
        use WaitPID::*;
        match self.wait_pid {
            Exited { pid, .. } => pid,
            Terminated { pid, .. } => pid,
            SysCall { pid, .. } => pid,
            PTraceEvent { pid, .. } => pid,
            Signal { pid, .. } => pid,
        }
    }

    pub fn exited(&self) -> bool {
        match self.state {
            StoppedProcessState::Exited => true,
            _ => false,
        }
    }

    pub fn event(&mut self) -> Result<ProcessEvent, OsError> {
        use WaitPID::*;
        let pid = self.id();
        let event = match self.wait_pid {
            Exited { exit_status, .. } => ProcessEventKind::ExitNormally(exit_status),
            Terminated { termination_signal, .. } => ProcessEventKind::ExitSignal(termination_signal),
            SysCall { .. } => {
                let state = self.tracer.child_states.entry(pid).or_insert(ChildState::UserSpace);
                let (sysinfo, new_child_state) = get_syscall_event_legacy(pid, *state)?;
                *state = new_child_state;
                sysinfo
            }
            PTraceEvent { message, kind, .. } => ProcessEventKind::Event { event_pid: message as u32, kind },
            Signal { signal, .. } => ProcessEventKind::SignalDelivery(signal),
        };

        Ok(ProcessEvent {
            pid,
            event,
        })
    }

    pub fn detach(mut self) -> Result<(), OsError> {
        p_trace_detach(self.id(), self.pending_signal())?;
        self.state = StoppedProcessState::Exited;
        Ok(())
    }

    pub fn keep_waiting(mut self) -> Result<(), OsError> {
        self.state = StoppedProcessState::Ignored;
        Ok(())
    }

    pub fn resume_with_syscall(mut self) -> Result<(), OsError> {
        p_trace_syscall(self.id(), self.pending_signal())?;
        self.state = StoppedProcessState::Resumed;
        Ok(())
    }

    pub fn resume(mut self) -> Result<(), OsError> {
        p_trace_cont(self.id(), self.pending_signal())?;
        self.state = StoppedProcessState::Resumed;
        Ok(())
    }

    pub fn pending_signal(&self) -> Option<c_int> {
        use WaitPID::*;
        match self.wait_pid {
            Signal { signal, .. } => Some(signal),
            _ => None,
        }
    }

    pub fn read_in_child_vm(&self, dest: &mut [u8], address: *const c_void) -> Result<usize, OsError> {
        safe_process_vm_readv(self.id(), dest, address)
    }

    pub fn read_os_string_in_child_vm(&self, address: *const c_void) -> Result<OsString, OsError> {
        let mut filepath_buffer = [0; 4096];
        let n = self.read_in_child_vm(&mut filepath_buffer, address)?;
        let string_size =  filepath_buffer.iter().position(|b| *b == b'\0').unwrap_or(n);
        use std::os::unix::ffi::OsStrExt;
        Ok(OsStr::from_bytes(&filepath_buffer[..string_size]).to_os_string())
    }

    pub fn from_wait_pid(tracer: &'a mut TracedChildTree, wait_pid: WaitPID) -> Self {
        use WaitPID::*;
        let state = match wait_pid {
            Exited { .. }
            | Terminated { .. } => StoppedProcessState::Exited,
            _ => StoppedProcessState::PTraceStop,
        };

        StoppedProcess {
            state,
            wait_pid,
            tracer,
        }
    }
}

impl<'a> Drop for StoppedProcess<'a> {
    fn drop(&mut self) {
        match self.state {
            StoppedProcessState::PTraceStop => {
                let _ = p_trace_detach(self.id(), self.pending_signal());
            }
            _ => (),
        }
    }
}

impl<'a> Debug for StoppedProcess<'a> {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        f.debug_struct("StoppedProcess")
            .field("state", &self.state)
            .field("wait_pid", &self.wait_pid)
            .field("tracer", &"<some tracer>")
            .finish()
    }
}
