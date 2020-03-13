use std::env::args_os;
use std::error::Error;
use std::process::Command;
use std::process::exit;

use slog::{Drain, error, info, Logger};
use slog_async;
use slog_term;

use dry;
use dry::{TracingCommand, ProcessEventAction, ProcessEventActor};

type DryError = Box<dyn Error + Send + Sync + 'static>;

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, slog::o!());

    let result = run(log.clone());

    let exitcode = match result {
        Ok(()) => 0,
        Err(e) => {
            error!(log, "{}", e);
            1
        }
    };

    drop(log);
    exit(exitcode)
}

fn run(log: Logger) -> Result<(), DryError> {
    let cmd= parse()?;
    let tracees = cmd.spawn_with_tracing()?;

    for ev in tracees.on_process_event(|e| ProcessEventActor::resume_with(())) {
        let ev = ev?;
        info!(log, "Got event {:?}", ev);
    }
    Ok(())
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
