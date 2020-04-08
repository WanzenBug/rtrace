use dry;
use cc;
use std::io::Write;
use dry::{TracingCommand, StoppedProcess};
use log::trace;
use sha2::{Sha256, Digest};

const CODE_PREFIX: &'static str = r#"
#include <unistd.h>
#include <sys/syscall.h>

void _start() {
"#;
const CODE_SUFFIX: &'static str = r#"
    syscall(SYS_exit, 0);
}
"#;

macro_rules! assert_next_event_matches {
    ($iter: expr, $( $pattern:pat )|+ $( if $guard: expr )?) => {
        assert_next_event_matches!($iter, $( $pattern )|+ $( if $guard )?, "Unexpected event")
    };
    ($iter: expr, $( $pattern:pat )|+ $( if $guard: expr )?, $message: literal) => {
        let ev = $iter.next()
            .expect("Expected next event to exist, got None instead")
            .expect("Expected next event to be read successfully, got error instead");
        match ev.event {
            $( $pattern )|+ $( if $guard )? => (),
            x => panic!("{}: Got {:?} instead", $message, x),
        }
    };
}

macro_rules! assert_iteration_end {
    ($iter: expr) => {
        assert!($iter.next().is_none(), "Expected iteration to end");
    };
    ($iter: expr, $message: literal) => {
        let ev = $iter.next();
        match ev {
            None => (),
            Some(x) => panic!("{}: Got {:?} instead", $message, x),
        };
    };
}


fn compile(c_code: &str, output_path: &std::path::Path) {
    trace!("Creating executable at: {}", output_path.display());
    let tool = cc::Build::new()
        .static_flag(true)
        .opt_level(0)
        .target("x86_64-unknown-linux-gnu")
        .host("x86_64-unknown-linux-gnu")
        .warnings(true)
        .warnings_into_errors(true)
        .get_compiler();

    assert!(tool.is_like_gnu() || tool.is_like_clang());

    let mut compiler_invocation = tool.to_command()
        .arg("-o")
        .arg(output_path)
        .arg("-nostartfiles")
        .arg("-x")
        .arg("c")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Compile should start");

    trace!("Writing code: {}", c_code);
    let mut code_pipe = compiler_invocation.stdin.take().expect("Stdin is piped");
    code_pipe.write_all(c_code.as_bytes()).expect("Pipe write to succeed");
    drop(code_pipe);
    let compiler_exit = compiler_invocation.wait().expect("Compiler should finish");
    assert!(compiler_exit.success(), "Compiler should compile code");
}

fn test_exe(c_code: &str) -> impl Iterator<Item=Result<dry::ProcessEvent, dry::OsError>> {
    let current_dir = std::path::Path::new(file!())
        .parent()
        .expect("Parent directory must exist");
    let test_exe_directory = current_dir.join("test_executables");
    std::fs::create_dir_all(&test_exe_directory).expect("Could not create test_executables directory");

    let full_code = [CODE_PREFIX, c_code, CODE_SUFFIX].join("");
    let hash = Sha256::digest(full_code.as_ref());
    let exec_path = test_exe_directory.join(hex::encode(&hash));

    if !exec_path.exists() {
        compile(&full_code, &exec_path);
    }

    let test_cmd = std::process::Command::new(exec_path)
        .spawn_with_tracing()
        .expect("Tracing should be possible");
    let mut iter = test_cmd.on_process_event(|mut stopped: StoppedProcess| {
        let ev = stopped.event()?;
        if !stopped.exited() {
            stopped.resume_with_syscall()?;
        }
        Ok(Some(ev))
    });

    assert_next_event_matches!(iter, dry::ProcessEventKind::SyscallEnter { syscall_number, ..} if syscall_number == libc::SYS_execve as u64, "Error in setup");
    assert_next_event_matches!(iter, dry::ProcessEventKind::Event { kind: dry::PTraceEventKind::Exec, ..}, "Error in setup");
    assert_next_event_matches!(iter, dry::ProcessEventKind::SyscallExit { is_error: false, .. }, "Error in setup");
    iter
}

#[test]
fn test_exit() {
    let mut process = test_exe("syscall(SYS_exit, 3);");

    // Receive syscall enter event
    assert_next_event_matches!(process, dry::ProcessEventKind::SyscallEnter {
        syscall_number,
        args: [3, 0, 0, 0, 0, 0],
    } if syscall_number == libc::SYS_exit as u64);

    // Receive ptrace event
    assert_next_event_matches!(process, dry::ProcessEventKind::Event {
        kind: dry::PTraceEventKind::Exit,
        ..
    });

    // Receive process exit (waitpid)
    assert_next_event_matches!(process, dry::ProcessEventKind::ExitNormally(3));

    // Process not running anymore
    assert_iteration_end!(process);
}
