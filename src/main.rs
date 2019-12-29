use std::process::Command;

use dry::{
    FingerprintEvent,
    TraceableCommand,
};
use std::collections::HashMap;
use std::ffi::CString;

type Error = Box<dyn std::error::Error + 'static>;

fn main() -> Result<(), Error> {
    let trace = Command::new("bash")
        .arg("-c")
        .arg("ls -lah /tmp")
        .spawn_traced()?;

    let mut touched = Vec::new();
    let mut last_touch = HashMap::<u32, CString>::new();
    for ev in trace {
        let mut ev = ev?;
        use FingerprintEvent::*;

        match ev.event() {
            SyscallEnter { syscall_number: 2, args } => {
                let s = ev.read_c_str(args[0])?;
                last_touch.insert(ev.pid(), s);
            }
            SyscallEnter { syscall_number: 59, args } => {
                let s = ev.read_c_str(args[0])?;
                last_touch.insert(ev.pid(), s);
            }
            SyscallEnter { syscall_number: 322, args } => {
                let s = ev.read_c_str(args[1])?;
                last_touch.insert(ev.pid(), s);
            }
            SyscallEnter { syscall_number: 257, args} => {
                let s = ev.read_c_str(args[1])?;
                last_touch.insert(ev.pid(), s);

            }
            SyscallEnter { syscall_number, .. } => eprintln!("{} Unknown({:?})", ev.pid(), syscall_number),
            SyscallExit { is_error, .. } => {
                if let Some(path) = last_touch.remove(&ev.pid()) {
                    touched.push((path, is_error, ev.pid()))
                }
            }
            _ => (),
        }
    }

    for (path, err, pid) in touched {
        if !err {
            println!("{}: {:?}\t{:?}", pid, !err, path);
        }
    }

    Ok(())
}
