use std::env::args_os;
use std::error::Error;
use std::process::Command;
use std::process::exit;

use log::debug;
use log::error;
use log::info;
use log::trace;
use pretty_env_logger;

use dry;
use dry::OsError;
use dry::ProcessEvent;
use dry::ProcessEventKind;
use dry::StoppedProcess;
use dry::TracingCommand;
use std::os::raw::c_void;
use std::ffi::{OsStr, OsString};

type DryError = Box<dyn Error + Send + Sync + 'static>;

fn main() {
    pretty_env_logger::init();

    let exitcode = match run() {
        Ok(()) => 0,
        Err(e) => {
            error!("{}", e);
            1
        }
    };

    exit(exitcode)
}

fn run() -> Result<(), DryError> {
    let mut cmd = parse()?;
    let tracees = cmd.spawn_with_tracing()?;

    for ev in tracees.on_process_event(filter_syscall_stops) {
        let ev = ev?;
        info!("Tracked {:?}", ev)
    }
    Ok(())
}

fn filter_syscall_stops(mut process: StoppedProcess) -> Result<Option<OsString>, OsError> {
    trace!("Trying to access user event");
    use ProcessEventKind::*;
    let mut filepath_buffer = [0; 4096];
    let ev = match process.event()?.kind() {
        SyscallEnter { syscall_number: 59, args} => {
            debug!("Entered execve()");
            let n = process.read_in_child_vm(&mut filepath_buffer, args[0] as *const c_void)?;

            let string_size =  filepath_buffer.iter().position(|b| *b == b'\0').unwrap_or(n);
            use std::os::unix::ffi::OsStrExt;
            Some((OsStr::from_bytes(&filepath_buffer[..string_size]).to_os_string()))
        }
        _ => None,
    };
    debug!("Got ProcessEvent: {:?}", ev);
    if !process.exited() {
        process.resume_with_syscall()?;
    }
    Ok(ev)
}

fn parse() -> Result<Command, DryError> {
    let mut prog_args = args_os();

    let _self_name = match prog_args.next() {
        Some(v) => v,
        None => Err("Cannot get program name")?,
    };

    let prog_name = match prog_args.next() {
        Some(v) => v,
        None => Err("Need at least a program name")?,
    };

    let mut cmd = Command::new(prog_name);
    cmd.args(prog_args);

    Ok(cmd)
}
