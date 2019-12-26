use std::process::Command;

use fingerprinter::{
    FingerprintEvent,
    TraceableCommand,
};

type Error = Box<dyn std::error::Error + 'static>;

fn main() -> Result<(), Error> {
    let trace = Command::new("bash")
        .arg("-c")
        .arg("ls -lah /tmp")
        .spawn_traced()?;
    eprintln!("trace = {:#?}", trace);
    for ev in trace {
        let mut ev = ev?;
        use FingerprintEvent::*;
        match ev.event() {
            SyscallEnter { syscall_number: 2, args } => {
                let s = ev.read_c_str(args[0])?;
                eprintln!("Open({:#?})", s);
            }
            SyscallEnter { syscall_number: 59, args } => {
                let s = ev.read_c_str(args[0])?;
                eprintln!("Exec({:#?})", s);
            }
            SyscallEnter { syscall_number: 322, args } => {
                let s = ev.read_c_str(args[1])?;
                eprintln!("ExecAt({:#?})", s);
            }
            SyscallEnter { syscall_number: 257, args} => {
                let s = ev.read_c_str(args[1])?;
                eprintln!("OpenAt({:#?})", s);
            }
            // SyscallEnter { syscall_number, .. } => eprintln!("Unknown({:?})", syscall_number),
            _ => (),
        }
    }

    Ok(())
}
