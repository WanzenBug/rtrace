use std::collections::HashMap;
use std::env::args;
use std::error::Error;
use std::ffi::OsString;
use std::fs::File;
use std::io::copy;
use std::io::ErrorKind;
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::exit;

use log::debug;
use log::error;
use log::trace;
use log::warn;
use pretty_env_logger;
use serde::Serialize;

use dry;
use dry::OsError;
use dry::ProcessEventKind;
use dry::StoppedProcess;
use dry::TracingCommand;
use md5::{Md5, Digest};

type DryError = Box<dyn Error + Send + Sync + 'static>;

fn main() {
    pretty_env_logger::init();

    let exitcode = match run() {
        Ok(()) => 0,
        Err(e) => {
            error!("{}", e);
            error!("Usage: dry run -f FILE command");
            1
        }
    };

    exit(exitcode)
}

fn run() -> Result<(), DryError> {
    let (dvc_file, cmd) = parse()?;
    let tracees = Command::new(&cmd[0])
        .args(&cmd[1..])
        .spawn_with_tracing()?;

    let repo_root = Path::new(".").canonicalize()?;

    let mut visited_files = HashMap::new();
    for ev in tracees.on_process_event(filter_successful_syscall()) {
        let ops = ev?;
        for op in ops {
            let path = PathBuf::from(op.location).canonicalize()?;
            if !path.starts_with(&repo_root) {
                continue;
            }

            if !path.is_file() {
                warn!("Skipping path {}, as its not a file", path.display());
                continue;
            }

            let entry = visited_files.entry(path).or_insert(Operation::Read);
            if op.operation == Operation::Write {
                *entry = Operation::Write;
            }
        }
    }

    let mut deps = Vec::new();
    let mut outs = Vec::new();

    for (full_path, mode) in visited_files {
        let in_repo_file = full_path.strip_prefix(&repo_root)?.to_path_buf();

        let string_path = match in_repo_file.to_str().map(ToString::to_string) {
            Some(x) => x,
            None => {
                warn!("Could not convert {} to string", in_repo_file.display());
                continue;
            }
        };

        match mode {
            Operation::Write => outs.push(DvcOuts {
                path: string_path,
                cache: true,
                md5: file_digest(&full_path)?,
            }),
            Operation::Read => deps.push(DvcDeps {
                path: string_path,
                md5: file_digest(&full_path)?,
            })
        }
    }

    let own_cmd = format!("dry run -f {}", dvc_file);
    let meta = vec![("created-by".to_string(), "dry".to_string())].into_iter().collect();
    let dvc_result = DvcStage {
        cmd: format!("{} {}", own_cmd, cmd.join(" ")),
        deps,
        md5: "".to_string(),
        outs,
        meta,
    };

    let file = File::create(dvc_file)?;
    serde_yaml::to_writer(file, &dvc_result)?;
    Ok(())
}

fn filter_successful_syscall() -> impl FnMut(StoppedProcess) -> Result<Option<Vec<FileOperation>>, OsError> {
    let mut syscall_memory: HashMap<i32, Vec<FileOperation>> = HashMap::new();

    move |mut process| {
        trace!("Trying to access user event");
        use ProcessEventKind::*;
        let ev = process.event()?;
        let ops = match ev.kind() {
            SyscallEnter { syscall_number, args } => {
                let ops = FileOperation::from_syscall(&process, *syscall_number, *args)?;
                let entry = syscall_memory.entry(process.id())
                    .or_default();
                if entry.len() != 0 {
                    warn!("Child process has stored {} file operations when there should not be any", process.id());
                }
                entry.extend(ops);
                None
            }
            SyscallExit { is_error: false, .. } => {
                let ret = syscall_memory.entry(process.id())
                    .or_default();
                if ret.len() == 0 {
                    None
                } else {
                    Some(ret.drain(..).collect())
                }
            }
            SyscallExit { is_error: true, .. } => {
                syscall_memory.entry(process.id()).or_default().clear();
                None
            }
            _ => None,
        };
        if !process.exited() {
            process.resume_with_syscall()?;
        }
        Ok(ops)
    }
}

fn parse() -> Result<(String, Vec<String>), DryError> {
    let mut prog_args = args();

    let _self_name = match prog_args.next() {
        Some(v) => v,
        None => Err("Cannot get program name")?,
    };

    let _run = match prog_args.next() {
        Some(ref x) if x == "run" => (),
        _ => Err("Expected 'run'")?,
    };

    let _flag = match prog_args.next() {
        Some(ref x) if x == "-f" || x == "--file" => (),
        _ => Err("Expected '-f' after 'run'")?,
    };

    let dvc_file = match prog_args.next() {
        Some(x) => x,
        _ => Err("Expected '-f' after 'run'")?,
    };

    let cmd: Vec<_> = prog_args.collect();
    if cmd.len() == 0 {
        Err("Expected at least a program name")?
    }

    Ok((dvc_file, cmd))
}


fn file_digest(path: &Path) -> Result<String, DryError> {
    let mut digest = Md5::new();
    let mut file = File::open(path)?;
    copy(&mut file, &mut digest)?;
    Ok(hex::encode(&digest.result()[..]))
}

#[derive(Debug, Serialize)]
struct DvcStage {
    cmd: String,
    md5: String,
    deps: Vec<DvcDeps>,
    outs: Vec<DvcOuts>,
    meta: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct DvcDeps {
    path: String,
    md5: String,
}

#[derive(Debug, Serialize)]
struct DvcOuts {
    path: String,
    cache: bool,
    md5: String,
}

#[derive(Debug)]
struct FileOperation {
    location: OsString,
    operation: Operation,
}

#[derive(Debug, PartialEq, Eq)]
enum Operation {
    Read,
    Write,
}

impl FileOperation {
    fn from_syscall(process: &StoppedProcess, syscall_number: u64, args: [u64; 6]) -> Result<Vec<Self>, OsError> {
        debug!("Decoding syscall: # {}, args: {:?}", syscall_number, args);
        match syscall_number as i64 {
            libc::SYS_execve => {
                debug!("Entered SYS_execve");
                let location = process.read_os_string_in_child_vm(args[0] as *const c_void)?;
                trace!("Got string {:?}", location);
                Ok(vec![FileOperation {
                    location,
                    operation: Operation::Read,
                }])
            }
            libc::SYS_open => {
                debug!("Entered SYS_open");
                let location = process.read_os_string_in_child_vm(args[0] as *const c_void)?;
                let operation = if (args[1] as i32 & libc::O_RDONLY) > 0 {
                    Operation::Read
                } else {
                    Operation::Write
                };
                Ok(vec![FileOperation {
                    location,
                    operation,
                }])
            }
            libc::SYS_openat => {
                debug!("Entered SYS_openat");
                if args[0] as i32 != libc::AT_FDCWD {
                    Err(OsError::new(ErrorKind::Other, "Currently all 'at' syscalls only support the special AT_FDCWD flag"))?
                }
                let location = process.read_os_string_in_child_vm(args[1] as *const c_void)?;
                let flags = args[2] as i32;
                let operation = if (flags & (libc::O_WRONLY | libc::O_RDWR)) > 0 {
                    Operation::Write
                } else {
                    Operation::Read
                };
                Ok(vec![FileOperation {
                    location,
                    operation,
                }])
            }
            libc::SYS_chdir
            | libc::SYS_fchdir => Err(OsError::new(ErrorKind::Other, "Currently changing directories is not tracked correctly"))?,
            _ => Ok(Vec::new()),
        }
    }
}
