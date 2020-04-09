use dry;
use cc;
use std::io::Write;
use dry::TracingCommand;
use dry::syscall_tracer::SyscallTracer;
use dry::syscall_tracer::Syscall;
use dry::syscall_tracer::SyscallKind;
use log::trace;
use sha2::Sha256;
use sha2::Digest;

const CODE_PREFIX: &'static str = r#"
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>

int main() {
    sched_yield();
"#;
const CODE_SUFFIX: &'static str = r#"
    return 0;
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
        match ev {
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
        .opt_level(0)
        .debug(true)
        .target("x86_64-unknown-linux-gnu")
        .host("x86_64-unknown-linux-gnu")
        .warnings(true)
        .warnings_into_errors(true)
        .get_compiler();

    assert!(tool.is_like_gnu() || tool.is_like_clang());

    let mut compiler_invocation = tool.to_command()
        .arg("-o")
        .arg(output_path)
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

fn test_exe(c_code: &str) -> impl Iterator<Item=Result<Syscall, dry::OsError>> {
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
    let mut iter = test_cmd.on_process_event(SyscallTracer::new());

    assert_next_event_matches!(iter, Syscall { kind: SyscallKind::Execve{ result: Ok(_), .. }, .. }, "Error in setup");
    loop {
        if let Syscall { kind: SyscallKind::SchedYield, .. } = iter.next().expect("Error in setup").expect("Error in setup") {
            break;
        }
    }
    iter
}

#[test]
fn test_exit() {
    let mut process = test_exe("syscall(SYS_exit, 3);");

    // Receive syscall enter event
    assert_next_event_matches!(process, Syscall { kind: SyscallKind::Exit { code: 3 }, .. });

    // Process not running anymore
    assert_iteration_end!(process);
}


#[test]
fn test_open() {
    let mut process = test_exe(r#"syscall(SYS_open, "/dev/null", 2);"#);
    assert_next_event_matches!(process, Syscall { kind: SyscallKind::Open { result: Ok(_), .. }, ..});
    assert_next_event_matches!(process, Syscall { kind: SyscallKind::ExitGroup { code: 0 }, .. });
    assert_iteration_end!(process);
}

#[test]
fn test_open_failure() {
    assert!(!std::path::Path::new("/dev/404").exists());
    let mut process = test_exe(r#"syscall(SYS_open, "/dev/404", 2);"#);
    assert_next_event_matches!(process, Syscall { kind: SyscallKind::Open { result: Err(_), .. }, ..});
    assert_next_event_matches!(process, Syscall { kind: SyscallKind::ExitGroup { code: 0 }, .. });
    assert_iteration_end!(process);
}
