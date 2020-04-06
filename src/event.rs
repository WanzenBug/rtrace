use libc::pid_t;
use crate::wait_pid::PTraceEventKind;

#[derive(Debug, Copy, Clone)]
pub struct ProcessEvent {
    pub pid: pid_t,
    pub event: ProcessEventKind,
}


impl ProcessEvent {
    pub fn pid(&self) -> pid_t {
        self.pid
    }

    pub fn kind(&self) -> &ProcessEventKind {
        &self.event
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProcessEventKind {
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
        kind: PTraceEventKind,
    },
    SignalDelivery(i32),
    ExitNormally(i32),
    ExitSignal(i32),
}
