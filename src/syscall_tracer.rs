use std::collections::HashMap;
use std::ffi::CString;
use std::io::ErrorKind;
use std::os::raw::c_void;
use std::path::PathBuf;
use std::sync::Arc;

use log::trace;

use crate::OsError;
use crate::ProcessEventKind;
use crate::RawTraceEventHandler;
use crate::StoppedProcess;

#[derive(Debug, Default)]
pub struct SyscallTracer {
    process_group_map: HashMap<i32, ProcessInformation>,
    process_tracker: HashMap<i32, Syscall>,
}

impl SyscallTracer {
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Debug)]
pub struct ProcessInformation {
    file_descriptors: HashMap<i32, Arc<PathBuf>>,
}

#[derive(Debug)]
pub struct Syscall {
    pub process: i32,
    pub kind: SyscallKind,
}

#[derive(Debug)]
pub enum SyscallKind {
    Open {
        path: Arc<PathBuf>,
        flags: i32,
        result: Result<i32, OsError>,
    },
    Execve {
        path: Arc<PathBuf>,
        args: Arc<Vec<CString>>,
        environ: Arc<Vec<CString>>,
        result: Result<(), OsError>,
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
        result: Result<(), OsError>,
    },
    Unknown {
        number: u64,
        args: [u64; 6],
        result: Result<u64, OsError>,
    },
}

#[derive(Debug)]
pub enum SyscallReturnValue {
    Open { file_descriptor: i32 }
}

impl RawTraceEventHandler for SyscallTracer {
    type IterationItem = Syscall;
    type Error = OsError;

    fn handle(&mut self, mut stop_event: StoppedProcess) -> Result<Option<Self::IterationItem>, Self::Error> {
        let ev = stop_event.event()?;

        match ev.kind() {
            ProcessEventKind::SyscallEnter { syscall_number, args } => {
                let call_info = Syscall::from_stopped_process(&mut stop_event, *syscall_number, *args)?;
                if let Some(x) = self.process_tracker.insert(ev.pid, call_info) {
                    Err(OsError::new(ErrorKind::Other, format!("Expected no previous entry for process {}, got {:?}", ev.pid, x)))
                } else {
                    Ok(None)
                }
            }
            ProcessEventKind::SyscallExit { is_error, return_val } => {
                let info = self.process_tracker.remove(&ev.pid)
                    .ok_or_else(|| OsError::new(ErrorKind::Other, format!("Got syscall exit event without stored enter information for process {}", ev.pid)))?;

                let call_info = info.update_from_retval(&mut stop_event, *is_error, *return_val)?;

                Ok(Some(call_info))
            }
            ProcessEventKind::ExitNormally(_) => {
                match self.process_tracker.remove(&ev.pid) {
                    Some(x @ Syscall { kind: SyscallKind::Exit { .. }, .. })
                    | Some( x @ Syscall { kind: SyscallKind::ExitGroup { .. }, .. })=> {
                        trace!("Process exited when executing exit syscall, as expected");
                        Ok(Some(x))
                    }
                    Some(x) => {
                        Err(OsError::new(ErrorKind::Other, format!("Process {} exited while executing syscall: {:?}", ev.pid, x.kind)))
                    }
                    None => {
                        Err(OsError::new(ErrorKind::Other, format!("Process {} exited without executing any syscall", ev.pid)))
                    }
                }
            }
            _ => Ok(None),
        }
    }
}

impl Syscall {
    #[cfg(target_arch = "x86_64")]
    fn from_stopped_process(process: &mut StoppedProcess, number: u64, args: [u64; 6]) -> Result<Self, OsError> {
        let kind = match number {
            2 => {
                let path = process.read_os_string_in_child_vm(args[0] as *const c_void)?;
                SyscallKind::Open {
                    path: Arc::new(PathBuf::from(path)),
                    flags: args[1] as i32,
                    result: Ok(0),
                }
            }
            24 => SyscallKind::SchedYield,
            59 => {
                let path = process.read_os_string_in_child_vm(args[0] as *const c_void)?;

                SyscallKind::Execve {
                    path: Arc::new(PathBuf::from(path)),
                    args: Arc::new(Vec::new()),
                    environ: Arc::new(Vec::new()),
                    result: Ok(()),
                }
            }
            60 => SyscallKind::Exit { code: args[0] as i32 },
            231 => SyscallKind::ExitGroup { code: args[0] as i32 },
            234 => {
                SyscallKind::TGKill {
                    group_id: args[0] as i32,
                    thread_id: args[1] as i32,
                    signal: args[3] as i32,
                    result: Ok(()),
                }
            }
            x => {
                SyscallKind::Unknown {
                    number: x,
                    args,
                    result: Ok(0),
                }
            }
        };
        Ok(Syscall {
            process: process.id(),
            kind,
        })
    }

    fn update_from_retval(mut self, _process: &mut StoppedProcess, is_error: bool, return_value: i64) -> Result<Self, OsError> {
        use SyscallKind::*;
        match &mut self.kind {
            Execve { result, .. }
            | TGKill { result, .. } => {
                if is_error {
                    *result = Err(OsError::from_raw_os_error(-return_value as i32));
                } else {
                    *result = Ok(());
                }
            }
            Open { result, .. } => {
                if is_error {
                    *result = Err(OsError::from_raw_os_error(-return_value as i32));
                } else {
                    *result = Ok(return_value as i32)
                }
            }
            Unknown { result, .. } => {
                if is_error {
                    *result = Err(OsError::from_raw_os_error(-return_value as i32));
                } else {
                    *result = Ok(return_value as u64)
                }
            }
            SchedYield => (),
            _ => unimplemented!(),
        }
        Ok(self)
    }
}