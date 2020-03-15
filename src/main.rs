use std::env::args_os;
use std::error::Error;
use std::process::Command;
use std::process::exit;

use dry;
use dry::{OsError, ProcessEvent, StoppedProcess, TracingCommand};
use log::error;
use log::info;
use pretty_env_logger;

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
        info!("Got event {:?}", ev);
    }
    Ok(())
}

fn filter_syscall_stops(mut process: StoppedProcess) -> Result<Option<ProcessEvent>, OsError> {
    info!("Trying to access user event");
    let ev = process.event()?;
    info!("Got ProcessEvent: {:?}", ev);
    if !process.exited() {
        process.resume_with_syscall()?;
    }
    Ok(Some(ev))
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
