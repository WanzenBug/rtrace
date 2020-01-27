use std::collections::HashMap;
use std::mem;
use std::process::Command;

use once_cell::sync::OnceCell;

use crate::raw::{ptrace, stop_self};
use crate::{Fingerprint, FingerprintEvent, Result, TraceeState};

#[must_use = "Traced child process cannot will not continue with monitoring"]
#[derive(Debug)]
pub struct TraceableChild {
    handle: (),
    children_map: HashMap<ptrace::PTracePID, ChildState>,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum ChildState {
    Normal,
    Syscall,
}

pub trait TraceableCommand {
    fn spawn_traced(self) -> Result<TraceableChild>;
}

impl TraceableCommand for Command {
    fn spawn_traced(mut self) -> Result<TraceableChild> {
        use std::os::unix::process::CommandExt;
        use std::sync::Arc;
        use std::sync::Barrier;

        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = barrier.clone();
        unsafe {
            self.pre_exec(move || {
                ptrace::trace_me().expect("trace_me() cannot fail");
                barrier_clone.wait();
                stop_self().expect("stop_self() cannot fail");
                Ok(())
            })
        };
        std::thread::spawn(move || self.exec());
        barrier.wait();
        let wait = ptrace::wait_for(-1)?;
        let pid = match wait {
            // SIGSTOP == 19 (on x86_64)
            ptrace::WaitPID::Signal { pid, signal: 19 } => pid,
            x => Err(format!(
                "Expected SIGSTOP in child process, got {:?} instead",
                x
            ))?,
        };
        ptrace::set_trace_syscall_option(pid)?;
        ptrace::trace_syscall_with_signal_delivery(pid, 0)?;

        Ok(TraceableChild {
            handle: (),
            children_map: HashMap::new(),
        })
    }
}

impl Iterator for TraceableChild {
    type Item = Result<Fingerprint>;

    fn next(&mut self) -> Option<Self::Item> {
        use ptrace::WaitPID::*;
        match ptrace::wait_all() {
            Ok(SysCall { pid }) => {
                static INSTANCE: OnceCell<bool> = OnceCell::new();
                let fast_syscall_info =
                    *INSTANCE.get_or_init(move || match ptrace::get_syscall_info_fast(pid) {
                        Ok(_) => true,
                        Err(ref e) if e.kind() == std::io::ErrorKind::InvalidInput => false,
                        Err(x) => panic!(
                            "Could not determine if PTRACE_GETSYSCALLINFO is supported, got {:?}",
                            x
                        ),
                    });

                let event = if fast_syscall_info {
                    match get_syscall_event(pid) {
                        Ok(e) => e,
                        Err(e) => return Some(Err(e)),
                    }
                } else {
                    let childstate = self.children_map.entry(pid).or_insert(ChildState::Normal);
                    match get_syscall_event_legacy(pid, *childstate) {
                        Ok((event, newstate)) => {
                            *childstate = newstate;
                            event
                        }
                        Err(e) => return Some(Err(e)),
                    }
                };
                Some(Ok(Fingerprint {
                    pid,
                    event,
                    state: TraceeState::Stopped,
                }))
            }
            Ok(NoChild) => None,
            Ok(Exited { pid, exit_status }) => Some(Ok(Fingerprint {
                pid,
                event: FingerprintEvent::ExitNormally(exit_status),
                state: TraceeState::Exited,
            })),
            Ok(Terminated {
                pid,
                termination_signal,
            }) => Some(Ok(Fingerprint {
                pid,
                event: FingerprintEvent::ExitSignal(termination_signal),
                state: TraceeState::Exited,
            })),
            Ok(Signal { pid, signal }) => Some(Ok(Fingerprint {
                pid,
                event: FingerprintEvent::SignalDelivery { signal },
                state: TraceeState::Stopped,
            })),
            Ok(PTraceEvent { pid, other_pid, ty }) => Some(Ok(Fingerprint {
                pid,
                event: FingerprintEvent::Event {
                    event_pid: other_pid as u32,
                    ty,
                },
                state: TraceeState::Stopped,
            })),
            Err(e) => Some(Err(e)),
        }
    }
}

fn get_syscall_event_legacy(
    pid: ptrace::PTracePID,
    state: ChildState,
) -> Result<(FingerprintEvent, ChildState)> {
    use ptrace::{UserRegs, UserRegsAMD64, UserRegsX86};
    let (syscall_number, args) = unsafe {
        match ptrace::get_process_registers(pid)? {
            (size, UserRegs { x86 }) if size == mem::size_of::<UserRegsX86>() => {
                Err(format!("x86 decding is not implemented yet: {:#?}", x86))?
            }
            (size, UserRegs { amd64 }) if size == mem::size_of::<UserRegsAMD64>() => (
                amd64.orig_rax,
                [
                    amd64.rdi, amd64.rsi, amd64.rdx, amd64.r10, amd64.r8, amd64.r9,
                ],
            ),
            _ => unimplemented!(),
        }
    };

    match state {
        ChildState::Normal => Ok((
            FingerprintEvent::SyscallEnter {
                syscall_number,
                args,
            },
            ChildState::Syscall,
        )),
        ChildState::Syscall => {
            let ret_val = syscall_number as i64;
            Ok((
                FingerprintEvent::SyscallExit {
                    return_val: ret_val,
                    is_error: ret_val < 0,
                },
                ChildState::Normal,
            ))
        }
    }
}

fn get_syscall_event(pid: ptrace::PTracePID) -> Result<FingerprintEvent> {
    use ptrace::{PtraceSyscallEventArgs, PtraceSyscallInfo};

    unsafe {
        match ptrace::get_syscall_info_fast(pid)? {
            PtraceSyscallInfo { op: 0, .. } => {
                Err(format!("Process {} not stopped because of syscall event", pid).into())
            }
            PtraceSyscallInfo {
                op: 1,
                event_args: PtraceSyscallEventArgs { entry },
                ..
            } => Ok(FingerprintEvent::SyscallEnter {
                syscall_number: entry.nr,
                args: entry.args,
            }),
            PtraceSyscallInfo {
                op: 2,
                event_args: PtraceSyscallEventArgs { exit },
                ..
            } => Ok(FingerprintEvent::SyscallExit {
                return_val: exit.rval,
                is_error: exit.is_error != 0,
            }),
            PtraceSyscallInfo { op: 3, .. } => Err("Got seccomp stop")?,
            PtraceSyscallInfo { op, .. } => Err(format!("Got unknown stop {}", op))?,
        }
    }
}
