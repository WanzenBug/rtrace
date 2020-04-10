use std::collections::HashMap;
use std::ffi::CString;
use std::io::ErrorKind;
use std::os::raw::c_void;
use std::path::PathBuf;
use std::sync::Arc;

use crate::OsError;
use crate::ProcessEventKind;
use crate::RawTraceEventHandler;
use crate::StoppedProcess;

#[derive(Debug, Default)]
pub struct EnhancedTracer {
    process_group_map: HashMap<i32, ProcessInformation>,
    process_tracker: HashMap<i32, SyscallEnter>,
}

impl EnhancedTracer {
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Debug)]
pub struct ProcessInformation {
    file_descriptors: HashMap<i32, Arc<PathBuf>>,
}

#[derive(Debug)]
pub struct EnhancedEvent {
    pub process: i32,
    pub kind: EnhancedEventKind,
}

#[derive(Debug)]
pub enum EnhancedEventKind {
    SyscallEnter(SyscallEnter),
    SyscallExit(SyscallResult),
    Exit(i32),
    SignalExit(i32),
}

#[derive(Debug, Clone)]
pub enum SyscallEnter {
    Open {
        path: Arc<PathBuf>,
        flags: i32,
    },
    Execve {
        path: Arc<PathBuf>,
        args: Arc<Vec<CString>>,
        environ: Arc<Vec<CString>>,
    },
    SchedYield,
    Exit {
        code: i32
    },
    ExitGroup {
        code: i32,
    },
    TGKill {
        group_id: i32,
        thread_id: i32,
        signal: i32,
    },
    Unknown {
        number: u64,
        args: [u64; 6],
    },
}

pub type SyscallResult = Result<SyscallExit, OsError>;

#[derive(Debug)]
pub enum SyscallExit {
    Open(i32),
    Execve,
    SchedYield,
    Exit,
    ExitGroup,
    TGKill,
    Unknown(i64),
}

#[derive(Debug)]
pub enum SyscallReturnValue {
    Open { file_descriptor: i32 }
}

impl RawTraceEventHandler for EnhancedTracer {
    type IterationItem = EnhancedEvent;
    type Error = OsError;

    fn handle(&mut self, mut stop_event: StoppedProcess) -> Result<Option<Self::IterationItem>, Self::Error> {
        let ev = stop_event.event()?;

        let kind = match ev.kind() {
            ProcessEventKind::SyscallEnter { syscall_number, args } => {
                let syscall_info = SyscallEnter::from_stopped_process(&mut stop_event, *syscall_number, *args)?;
                if let Some(x) = self.process_tracker.insert(ev.pid, syscall_info.clone()) {
                    return Err(OsError::new(ErrorKind::Other, format!("Expected no previous entry for process {}, got {:?}", ev.pid, x)));
                }
                EnhancedEventKind::SyscallEnter(syscall_info)
            }
            ProcessEventKind::SyscallExit { is_error, return_val } => {
                let enter_info = self.process_tracker.remove(&ev.pid)
                    .ok_or_else(|| OsError::new(ErrorKind::Other, format!("Got syscall exit event without stored enter information for process {}", ev.pid)))?;

                let exit_info = SyscallExit::from_stopped_process(&mut stop_event, enter_info, *is_error, *return_val)?;
                EnhancedEventKind::SyscallExit(exit_info)
            }
            ProcessEventKind::Event { .. } => {
                return Ok(None);
            }
            ProcessEventKind::ExitNormally(x) => {
                self.process_tracker.remove(&ev.pid);
                EnhancedEventKind::Exit(*x)
            }
            ProcessEventKind::ExitSignal(x) => EnhancedEventKind::SignalExit(*x),
            _ => unimplemented!(),
        };
        Ok(Some(EnhancedEvent {
            process: ev.pid,
            kind,
        }))
    }
}

impl SyscallEnter {
    #[cfg(target_arch = "x86_64")]
    fn from_stopped_process(process: &mut StoppedProcess, number: u64, args: [u64; 6]) -> Result<Self, OsError> {
        let kind = match number {
            2 => {
                let path = process.read_os_string_in_child_vm(args[0] as *const c_void)?;
                SyscallEnter::Open {
                    path: Arc::new(PathBuf::from(path)),
                    flags: args[1] as i32,
                }
            }
            24 => SyscallEnter::SchedYield,
            59 => {
                let path = process.read_os_string_in_child_vm(args[0] as *const c_void)?;

                SyscallEnter::Execve {
                    path: Arc::new(PathBuf::from(path)),
                    args: Arc::new(Vec::new()),
                    environ: Arc::new(Vec::new()),
                }
            }
            60 => SyscallEnter::Exit { code: args[0] as i32 },
            231 => SyscallEnter::ExitGroup { code: args[0] as i32 },
            234 => {
                SyscallEnter::TGKill {
                    group_id: args[0] as i32,
                    thread_id: args[1] as i32,
                    signal: args[3] as i32,
                }
            }
            x => {
                SyscallEnter::Unknown {
                    number: x,
                    args,
                }
            }
        };
        Ok(kind)
    }
}

impl SyscallExit {
    fn from_stopped_process(_process: &mut StoppedProcess, enter_call: SyscallEnter, is_error: bool, return_value: i64) -> Result<Result<Self, OsError>, OsError> {
        use SyscallEnter::*;
        if is_error {
            return Ok(Err(OsError::from_raw_os_error(-return_value as i32)));
        }

        let kind = match enter_call {
            Execve { .. } => SyscallExit::Execve,
            TGKill { .. } => SyscallExit::TGKill,
            SchedYield => SyscallExit::SchedYield,
            Open { .. } => SyscallExit::Open(return_value as i32),
            Unknown { .. } => SyscallExit::Unknown(return_value),
            _ => unimplemented!(),
        };
        Ok(Ok(kind))
    }
}