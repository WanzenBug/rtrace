use std::collections::HashMap;
use std::env::args_os;
use std::ffi::CString;
use std::process::Command;

use dry::{
    FingerprintEvent,
    TraceableCommand,
};

type Error = Box<dyn std::error::Error + 'static>;

fn main() -> Result<(), Error> {
    let mut args = args_os();
    let _current_prog = args.next();
    let prog = match args.next() {
        Some(v) => v,
        None => return Err("Need to specify a program to run".into()),
    };

    let trace = Command::new(prog)
        .args(args)
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
            SyscallEnter { syscall_number: 257, args } => {
                let s = ev.read_c_str(args[1])?;
                last_touch.insert(ev.pid(), s);
            }
            SyscallExit { is_error, .. } => {
                if let Some(path) = last_touch.remove(&ev.pid()) {
                    touched.push((path, is_error, ev.pid()))
                }
            }
            _ => (),
        }
    }

    for (path, err, pid) in touched {
        println!("{}: {:?}  \t{:?}", pid, !err, path);
    }

    Ok(())
}
