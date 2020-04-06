use dry;
use cc;
use tempfile;
use std::io::Write;
use dry::TracingCommand;

const CODE_PREFIX: &'static str = r#"
#include <unistd.h>
#include <sys/syscall.h>

void _start() {
"#;
const CODE_SUFFIX: &'static str = r#"
    syscall(SYS_exit, 0);
}
"#;

fn compile(c_code: &str) -> impl Iterator<Item=Result<dry::ProcessEvent, dry::OsError>> {
    let tempdir = tempfile::tempdir().expect("Could not create temporary directory");
    let exec_path = tempdir.path().join("test_exec");

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
        .arg(&exec_path)
        .arg("-nostartfiles")
        .arg("-x")
        .arg("c")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Compile should start");

    eprintln!("Writing code: {}{}{}", CODE_PREFIX, c_code, CODE_SUFFIX);
    let mut code_pipe = compiler_invocation.stdin.take().expect("Stdin is piped");
    code_pipe.write_all(CODE_PREFIX.as_bytes()).expect("Pipe write to succeed");
    code_pipe.write_all(c_code.as_bytes()).expect("Pipe write to succeed");
    code_pipe.write_all(CODE_SUFFIX.as_bytes()).expect("Pipe write to succeed");
    drop(code_pipe);
    let compiler_exit = compiler_invocation.wait().expect("Compiler should finish");
    assert!(compiler_exit.success(), "Compiler should compile code");

    let test_cmd = std::process::Command::new(exec_path)
        .spawn_with_tracing()
        .expect("Tracing should be possible");
    let mut iter = test_cmd.on_process_event::<_, _, dry::OsError>(|mut stopped| {
        let ev = stopped.event()?;
        if !stopped.exited() {
            stopped.resume_with_syscall()?;
        }
        Ok(Some(ev))
    });

    let execve_enter_event = iter.next()
        .expect("execve() to be called")
        .expect("execve() to be called");
    assert!(matches!(execve_enter_event.event, dry::ProcessEventKind::SyscallEnter { syscall_number: 59, ..}));

    let execve_ptrace_stop_event = iter.next()
        .expect("execve() to be called")
        .expect("execve() to be called");
    assert!(matches!(execve_ptrace_stop_event.event, dry::ProcessEventKind::Event { kind: dry::PTraceEventKind::Exec, ..}));

    let execve_exit_event = iter.next()
        .expect("execve() to be called")
        .expect("execve() to be called");
    assert!(matches!(execve_exit_event.event, dry::ProcessEventKind::SyscallExit { is_error: false, .. }));
    iter
}

#[test]
fn test_exit() {
    let mut process = compile("syscall(SYS_exit, 3);");

    let ev = process.next()
        .expect("Expected syscall event")
        .expect("Syscall should be readable");

    // Call exit syscall
    assert_eq!(ev.event, dry::ProcessEventKind::SyscallEnter {
        syscall_number: libc::SYS_exit as u64,
        args: [3, 0, 0, 0, 0, 0],
    });

    // Receive ptrace event
    let ev = process.next()
        .expect("Expected syscall event")
        .expect("Syscall should be readable");
    assert!(matches!(ev.event, dry::ProcessEventKind::Event {
        kind: dry::PTraceEventKind::Exit,
        ..
    }));

    // Receive process exit (waitpid)
    let ev = process.next()
        .expect("Expected syscall event")
        .expect("Syscall should be readable");
    assert!(matches!(ev.event, dry::ProcessEventKind::ExitNormally(3)));

    // Process not running anymore
    assert!(process.next().is_none());
}
