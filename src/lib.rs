use std::{
    ffi::{OsStr, OsString},
    io::ErrorKind,
};

pub use command::{TraceableChild, TraceableCommand};

pub mod fs;
pub mod paths;
pub mod util;

mod raw;

const MAX_FILE_PATH_LENGTH: usize = 4096;

pub type Error = Box<dyn std::error::Error + 'static>;
pub type Result<T> = std::result::Result<T, Error>;

mod command;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TraceeState {
    Stopped,
    Exited,
    Resumed,
}

#[must_use]
#[derive(Debug)]
pub struct Fingerprint {
    pid: i32,
    event: FingerprintEvent,
    state: TraceeState,
}

#[derive(Debug, Copy, Clone)]
pub enum FingerprintEvent {
    SyscallEnter {
        syscall_number: u64,
        args: [u64; 6],
    },
    SyscallExit {
        return_val: i64,
        is_error: bool,
    },
    Event {
        event_pid: u32,
        ty: raw::ptrace::PtraceEventTy,
    },
    SignalDelivery {
        signal: i32,
    },
    ExitNormally(i32),
    ExitSignal(i32),
}

impl Fingerprint {
    pub fn resume(&mut self) -> Result<()> {
        if self.state != TraceeState::Stopped {
            return Ok(());
        }
        let signal = match self.event {
            FingerprintEvent::SignalDelivery { signal } => signal,
            _ => 0,
        };
        raw::ptrace::trace_syscall_with_signal_delivery(self.pid, signal)?;
        self.state = TraceeState::Resumed;
        Ok(())
    }

    pub fn read_os_string(&mut self, base_address: u64) -> Result<OsString> {
        if self.state != TraceeState::Stopped {
            Err(std::io::Error::from(ErrorKind::PermissionDenied))?;
        }
        let mut buf = [0; MAX_FILE_PATH_LENGTH];
        raw::ptrace::read_from_process(self.pid, &mut buf, base_address)?;
        let first_null = buf[..].iter().position(|&x| x == b'\0').ok_or_else(|| {
            format!(
                "Could not find CString in process {} at address {:x}",
                self.pid, base_address
            )
        })?;

        use std::os::unix::ffi::OsStrExt;
        Ok(OsStr::from_bytes(&buf[..first_null]).to_os_string())
    }

    pub fn event(&self) -> FingerprintEvent {
        self.event
    }

    pub fn pid(&self) -> u32 {
        self.pid as u32
    }
}

impl Drop for Fingerprint {
    fn drop(&mut self) {
        let _ = self.resume();
    }
}
