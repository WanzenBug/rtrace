use log::error;
use pretty_env_logger;
use rtrace::enhanced_tracer::EnhancedTracer;
use rtrace::TracingCommand;
use std::env::args_os;
use std::error::Error;
use std::ffi::OsString;
use std::process::{exit, Command};

type RTraceError = Box<dyn Error + Send + Sync + 'static>;

fn main() {
    pretty_env_logger::init();

    let exitcode = match run() {
        Ok(()) => 0,
        Err(e) => {
            error!("{}", e);
            error!("Usage: rtrace <command> <arg>...");
            1
        }
    };

    exit(exitcode)
}

fn run() -> Result<(), RTraceError> {
    let (cmd, args) = parse()?;

    let child = Command::new(cmd).args(args).spawn_with_tracing()?;

    for event in child.on_process_event(EnhancedTracer::new()) {
        let event = event?;

        eprintln!("{:?}", event);
    }

    Ok(())
}

fn parse() -> Result<(OsString, Vec<OsString>), RTraceError> {
    let mut prog_args = args_os();

    let _self_name = prog_args.next().ok_or("Expected program name")?;

    let command = prog_args.next().ok_or("Expected command to execute")?;

    let args: Vec<_> = prog_args.collect();

    Ok((command, args))
}
