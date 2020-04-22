use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;

pub use syscall_defs::SyscallEnter;
pub use syscall_defs::SyscallExit;

use crate::OsError;
use crate::ProcessEventKind;
use crate::RawTraceEventHandler;
use crate::StoppedProcess;

pub mod syscall_defs;

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
    SyscallExit(SyscallExit),
    Exit(i32),
    SignalExit(i32),
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
                    SyscallEnter::from_args_x86_64(*syscall_number, *args, &stop_event)?;
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
            ProcessEventKind::SyscallExit { return_val, .. } => {
                let enter_info = self.process_tracker.remove(&ev.pid)
                    .ok_or_else(|| OsError::new(ErrorKind::Other, format!("Got syscall exit event without stored enter information for process {}", ev.pid)))?;

                let exit_info =
                    SyscallExit::from_enter_event(enter_info, *return_val, &stop_event)?;
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
