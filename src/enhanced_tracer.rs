use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::mem::size_of;
use std::mem::transmute;
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
    Read {
        file_descriptor: i32,
        buf: *mut c_void,
        length: usize,
    },
    FStat {
        file_descriptor: i32,
        dest: *mut c_void,
    },
    Open {
        path: Arc<PathBuf>,
        flags: i32,
    },
    Close {
        file_descriptor: i32,
    },
    Stat {
        path: Arc<PathBuf>,
        dest: *mut c_void,
    },
    Execve {
        path: Arc<PathBuf>,
        args: Arc<Vec<CString>>,
        environ: Arc<Vec<CString>>,
    },
    SchedYield,
    Exit {
        code: i32,
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
    Read(usize),
    Open(i32),
    Close,
    Execve,
    SchedYield,
    Exit,
    ExitGroup,
    TGKill,
    Stat(Stat),
    FStat(Stat),
    Unknown(i64),
}

pub struct Stat(pub libc::stat);

impl Debug for Stat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Stat")
            .field("dev", &self.0.st_dev)
            .field("ino", &self.0.st_ino)
            // TODO: add more fields
            .finish()
    }
}

impl From<libc::stat> for Stat {
    fn from(v: libc::stat) -> Self {
        Stat(v)
    }
}

impl RawTraceEventHandler for EnhancedTracer {
    type IterationItem = EnhancedEvent;
    type Error = OsError;

    fn handle(
        &mut self,
        mut stop_event: StoppedProcess,
    ) -> Result<Option<Self::IterationItem>, Self::Error> {
        let ev = stop_event.event()?;

        let kind = match ev.kind() {
            ProcessEventKind::SyscallEnter {
                syscall_number,
                args,
            } => {
                let syscall_info =
                    SyscallEnter::from_stopped_process(&mut stop_event, *syscall_number, *args)?;
                if let Some(x) = self.process_tracker.insert(ev.pid, syscall_info.clone()) {
                    return Err(OsError::new(
                        ErrorKind::Other,
                        format!(
                            "Expected no previous entry for process {}, got {:?}",
                            ev.pid, x
                        ),
                    ));
                }
                EnhancedEventKind::SyscallEnter(syscall_info)
            }
            ProcessEventKind::SyscallExit {
                is_error,
                return_val,
            } => {
                let enter_info = self.process_tracker.remove(&ev.pid)
                    .ok_or_else(|| OsError::new(ErrorKind::Other, format!("Got syscall exit event without stored enter information for process {}", ev.pid)))?;

                let exit_info = SyscallExit::from_stopped_process(
                    &mut stop_event,
                    enter_info,
                    *is_error,
                    *return_val,
                )?;
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
    fn from_stopped_process(
        process: &mut StoppedProcess,
        number: u64,
        args: [u64; 6],
    ) -> Result<Self, OsError> {
        let kind = match number {
            0 => SyscallEnter::Read {
                file_descriptor: args[0] as i32,
                buf: args[1] as *mut c_void,
                length: args[2] as usize,
            },
            2 => {
                let path = process.read_os_string_in_child_vm(args[0] as *const c_void)?;
                SyscallEnter::Open {
                    path: Arc::new(PathBuf::from(path)),
                    flags: args[1] as i32,
                }
            }
            3 => SyscallEnter::Close {
                file_descriptor: args[0] as i32,
            },
            4 => {
                let path = process.read_os_string_in_child_vm(args[0] as *const c_void)?;

                SyscallEnter::Stat {
                    path: Arc::new(PathBuf::from(path)),
                    dest: args[1] as *mut c_void,
                }
            }
            5 => SyscallEnter::FStat {
                file_descriptor: args[0] as i32,
                dest: args[1] as *mut c_void,
            },
            24 => SyscallEnter::SchedYield,
            59 => {
                let path = process.read_os_string_in_child_vm(args[0] as *const c_void)?;

                SyscallEnter::Execve {
                    path: Arc::new(PathBuf::from(path)),
                    args: Arc::new(Vec::new()),
                    environ: Arc::new(Vec::new()),
                }
            }
            60 => SyscallEnter::Exit {
                code: args[0] as i32,
            },
            231 => SyscallEnter::ExitGroup {
                code: args[0] as i32,
            },
            234 => SyscallEnter::TGKill {
                group_id: args[0] as i32,
                thread_id: args[1] as i32,
                signal: args[3] as i32,
            },
            x => SyscallEnter::Unknown { number: x, args },
        };
        Ok(kind)
    }
}

impl SyscallExit {
    fn from_stopped_process(
        process: &mut StoppedProcess,
        enter_call: SyscallEnter,
        is_error: bool,
        return_value: i64,
    ) -> Result<Result<Self, OsError>, OsError> {
        use SyscallEnter::*;
        if is_error {
            return Ok(Err(OsError::from_raw_os_error(-return_value as i32)));
        }

        let kind = match enter_call {
            Read { .. } => SyscallExit::Read(return_value as usize),
            Close { .. } => SyscallExit::Close,
            Execve { .. } => SyscallExit::Execve,
            TGKill { .. } => SyscallExit::TGKill,
            SchedYield => SyscallExit::SchedYield,
            Open { .. } => SyscallExit::Open(return_value as i32),
            Unknown { .. } => SyscallExit::Unknown(return_value),
            Stat { dest, .. } => {
                let mut buf = [0; size_of::<libc::stat>()];
                let n = process.read_in_child_vm(&mut buf, dest)?;
                if buf.len() != n {
                    return Err(OsError::new(
                        ErrorKind::Other,
                        "Cannot read stat struct from process",
                    ));
                }
                let stat: libc::stat = unsafe { transmute(buf) };
                SyscallExit::Stat(stat.into())
            }
            FStat { dest, .. } => {
                let mut buf = [0; size_of::<libc::stat>()];
                let n = process.read_in_child_vm(&mut buf, dest)?;
                if buf.len() != n {
                    return Err(OsError::new(
                        ErrorKind::Other,
                        "Cannot read stat struct from process",
                    ));
                }
                let stat: libc::stat = unsafe { transmute(buf) };
                SyscallExit::FStat(stat.into())
            }
            Exit { code: _ } => unreachable!("exit syscall never returns"),
            ExitGroup { code: _ } => unreachable!("exit_group syscall never returns"),
        };
        Ok(Ok(kind))
    }
}
