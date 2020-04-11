use std::fmt::Debug;
use std::io::ErrorKind;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::os::raw::c_long;
use std::os::raw::c_void;
use std::os::raw::{c_int, c_ulong, c_ulonglong};
use std::ptr::null_mut;

use libc::close;
use libc::iovec;
use libc::pid_t;
use libc::pipe2;
use libc::process_vm_readv;
use libc::ptrace;
use libc::read;
use libc::sysconf;
use libc::waitpid;
use libc::O_CLOEXEC;
use libc::PTRACE_ATTACH;
use libc::PTRACE_CONT;
use libc::PTRACE_DETACH;
use libc::PTRACE_GETEVENTMSG;
use libc::PTRACE_INTERRUPT;
use libc::PTRACE_SEIZE;
use libc::PTRACE_SETOPTIONS;
use libc::PTRACE_SYSCALL;
use libc::_SC_PAGESIZE;
use log::debug;
use log::trace;
use once_cell::sync::Lazy;

use crate::event::ProcessEventKind;
use crate::OsError;
use std::cmp;

pub type PTraceRequest = libc::c_uint;

pub fn wait_pid(pid: pid_t, options: c_int) -> Result<(pid_t, WaitPIDStatus), OsError> {
    let mut status = 0;

    let pid =
        unsafe { check_ret_with_retry(|| waitpid(pid, &mut status as *mut c_int, options), -1) }?;
    Ok((pid, WaitPIDStatus(status)))
}

pub fn p_trace_detach(pid: pid_t, signum: Option<c_int>) -> Result<(), OsError> {
    unsafe { p_trace(PTRACE_DETACH, pid, None, signum.map(|x| x as *mut c_void)) }?;
    Ok(())
}

pub fn p_trace_cont(pid: pid_t, signum: Option<c_int>) -> Result<(), OsError> {
    unsafe { p_trace(PTRACE_CONT, pid, None, signum.map(|x| x as *mut c_void)) }?;
    Ok(())
}

pub fn p_trace_syscall(pid: pid_t, signum: Option<c_int>) -> Result<(), OsError> {
    unsafe { p_trace(PTRACE_SYSCALL, pid, None, signum.map(|x| x as *mut c_void)) }?;
    Ok(())
}

static IS_P_TRACE_SEIZE_SUPPORTED: Lazy<bool> = Lazy::new(|| {
    // Inspired by strace:
    // https://github.com/strace/strace/blob/d9b459ca120136efa5515064b56f13f8b8ed2022/strace.c#L1641

    let child_pid =
        match unsafe { fork() }.expect("Cannot fork() to determine PTRACE_SEIZE support") {
            ForkResult::Child => {
                // Child process, just pause and exit...
                unsafe {
                    libc::pause();
                    libc::_exit(0);
                }
            }
            ForkResult::Parent { child_pid } => child_pid,
        };

    let seize_works = match unsafe { p_trace(PTRACE_SEIZE, child_pid, None, None) } {
        Ok(_) => true,
        Err(e) => {
            trace!("PTRACE_SEIZE returned with error: {}", e);
            debug!("PTRACE_SEIZE does not work");
            false
        }
    };

    unsafe { libc::kill(child_pid, libc::SIGKILL) };

    let (_pid, status) = wait_pid(child_pid, 0).expect("Unexpected wait_pid result");
    if !status.signaled() {
        panic!("Unexpected wait_pid status: {:?}", status)
    }
    seize_works
});

pub fn p_trace_become_tracer(pid: pid_t) -> Result<(), OsError> {
    let options = libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEEXIT;

    if *IS_P_TRACE_SEIZE_SUPPORTED {
        p_trace_become_tracer_via_seize(pid, options)
    } else {
        p_trace_become_tracer_via_attach(pid, options)
    }
}

fn p_trace_become_tracer_via_seize(pid: pid_t, options: c_int) -> Result<(), OsError> {
    debug!("Calling PTRACE_SEIZE and PTRACE_INTERRUPT on child process");
    unsafe {
        p_trace(PTRACE_SEIZE, pid, None, Some(options as *mut c_void))?;
        p_trace(PTRACE_INTERRUPT, pid, None, None)?;
    }
    debug!("PTRACE_SEIZE and PTRACE_INTERRUPT successful");

    debug!("Syncing up to child process via waitpid(), waiting for PTRACE_STOP_EVENT");
    let (_pid, status) = wait_pid(pid, 0)?;
    match status.ptrace_event() {
        // NB: not exported by libc right now
        128 => Ok(()),
        x => Err(OsError::new(
            ErrorKind::Other,
            format!(
                "Got unexpected trace event {}, expected PTRACE_EVENT_STOP (128)",
                x
            ),
        )),
    }
}

fn p_trace_become_tracer_via_attach(pid: pid_t, options: c_int) -> Result<(), OsError> {
    debug!("Calling PTRACE_ATTACH on child process");
    unsafe { p_trace(PTRACE_ATTACH, pid, None, None) }?;
    // ATTACH will stop the child, however it is not guaranteed to be the first noticeable event
    debug!("PTRACE_ATTACH successful, awaiting injected SIGSTOP signal");
    loop {
        let (_pid, status) = wait_pid(pid, 0)?;
        if !status.stopped() {
            Err(OsError::new(
                ErrorKind::Other,
                format!(
                    "Got unexpected event from child before attach was completed: {:?}",
                    status
                ),
            ))?
        }

        match status.stop_signal() {
            libc::SIGSTOP => break,
            x => {
                trace!("Got signal: {}, re-injecting into child", x);
                unsafe { p_trace(PTRACE_CONT, pid, None, Some(x as *mut c_void)) }?
            }
        };
    }
    debug!("Got expected SIGSTOP in child, setting options");
    // Child is stopped here, in the SIGSTOP injected by PTRACE_ATTACH. Now we can safely set all
    // the options we want
    unsafe { p_trace(PTRACE_SETOPTIONS, pid, None, Some(options as *mut c_void)) }?;
    debug!("PTRACE_SETOPTIONS successful, child process is configured");
    Ok(())
}

pub fn p_trace_get_event_message(pid: pid_t) -> Result<c_ulong, OsError> {
    let mut message = 0;
    unsafe {
        p_trace(
            PTRACE_GETEVENTMSG,
            pid,
            None,
            Some(&mut message as *mut c_ulong as *mut c_void),
        )
    }?;
    Ok(message)
}

unsafe fn p_trace(
    req: PTraceRequest,
    pid: pid_t,
    addr: Option<*mut c_void>,
    data: Option<*mut c_void>,
) -> Result<c_long, OsError> {
    let x = check_ret(
        move || {
            ptrace(
                req,
                pid,
                addr.unwrap_or(null_mut()),
                data.unwrap_or(null_mut()),
            )
        },
        -1,
    )?;
    Ok(x)
}

pub unsafe fn fork() -> Result<ForkResult, OsError> {
    match check_ret(move || libc::fork(), -1)? {
        0 => Ok(ForkResult::Child),
        child_pid => Ok(ForkResult::Parent { child_pid }),
    }
}

pub fn get_syscall_number(child_pid: pid_t) -> Result<i64, OsError> {
    match get_registers(child_pid)? {
        UserRegs::AMD64(amd64) => Ok(amd64.orig_rax as i64),
        UserRegs::X86(x86) => Ok(x86.orig_eax as i64),
    }
}

#[derive(Debug, Copy, Clone)]
pub struct WaitPIDStatus(pub c_int);

impl WaitPIDStatus {
    pub fn exited(&self) -> bool {
        unsafe { libc::WIFEXITED(self.0) }
    }

    pub fn exit_status(&self) -> i32 {
        unsafe { libc::WEXITSTATUS(self.0) }
    }

    pub fn signaled(&self) -> bool {
        unsafe { libc::WIFSIGNALED(self.0) }
    }

    pub fn termination_signal(&self) -> i32 {
        unsafe { libc::WTERMSIG(self.0) }
    }

    pub fn stopped(&self) -> bool {
        unsafe { libc::WIFSTOPPED(self.0) }
    }

    pub fn stop_signal(&self) -> i32 {
        unsafe { libc::WSTOPSIG(self.0) }
    }

    pub fn syscalled(&self) -> bool {
        unsafe { libc::WSTOPSIG(self.0) == (libc::SIGTRAP | 0x80) }
    }

    pub fn ptrace_event(&self) -> i32 {
        self.0 >> 16
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ChildState {
    UserSpace,
    KernelSpace,
}

pub fn get_registers(pid: pid_t) -> Result<UserRegs, OsError> {
    let mut regs = MaybeUninit::<UserRegsUnion>::uninit();
    let size = std::mem::size_of_val(&regs);

    let mut iovec = libc::iovec {
        iov_base: regs.as_mut_ptr() as *mut c_void,
        iov_len: size,
    };
    let regs = unsafe {
        p_trace(
            libc::PTRACE_GETREGSET,
            pid,
            Some(1 as *mut c_void),
            Some(&mut iovec as *mut iovec as *mut c_void),
        )?;
        regs.assume_init()
    };

    unsafe {
        match (iovec.iov_len, regs) {
            (size, UserRegsUnion { x86 }) if size == size_of::<UserRegsX86>() => {
                Ok(UserRegs::X86(x86))
            }
            (size, UserRegsUnion { amd64 }) if size == size_of::<UserRegsAMD64>() => {
                Ok(UserRegs::AMD64(amd64))
            }
            _ => Err(OsError::new(
                ErrorKind::Other,
                "Got unexpected size of payload for PTRACE_GETREGSET",
            )),
        }
    }
}

pub fn get_syscall_event_legacy(
    pid: pid_t,
    state: ChildState,
) -> Result<(ProcessEventKind, ChildState), OsError> {
    let (syscall_number, args, ret_val) = match get_registers(pid)? {
        UserRegs::X86(x86) => unimplemented!("Decoding for x86 not implemented yet! {:?}", x86),
        UserRegs::AMD64(amd64) => (
            amd64.orig_rax,
            [
                amd64.rdi, amd64.rsi, amd64.rdx, amd64.r10, amd64.r8, amd64.r9,
            ],
            amd64.rax,
        ),
    };

    match state {
        ChildState::UserSpace => Ok((
            ProcessEventKind::SyscallEnter {
                syscall_number,
                args,
            },
            ChildState::KernelSpace,
        )),
        ChildState::KernelSpace => {
            let ret_val = ret_val as i64;
            Ok((
                ProcessEventKind::SyscallExit {
                    return_val: ret_val,
                    is_error: ret_val < 0,
                },
                ChildState::UserSpace,
            ))
        }
    }
}

pub unsafe fn pipe() -> Result<(c_int, c_int), OsError> {
    let mut result = [0, 0];
    check_ret(|| pipe2(result.as_mut_ptr(), O_CLOEXEC), -1)?;
    Ok((result[1], result[0]))
}

pub unsafe fn read_wait(fd: c_int) -> Result<(), OsError> {
    let mut buf = [0u8];
    match check_ret_with_retry(|| read(fd, buf.as_mut_ptr() as *mut c_void, 1), -1)? {
        0 => Ok(()),
        _ => Err(OsError::new(
            ErrorKind::Other,
            "Read data when there should be nothing to read",
        )),
    }
}

pub unsafe fn fd_close(fd: c_int) -> Result<(), OsError> {
    check_ret_with_retry(|| close(fd), -1)?;
    Ok(())
}

static PAGESIZE: Lazy<usize> = Lazy::new(|| {
    let pagesize =
        unsafe { check_ret(|| sysconf(_SC_PAGESIZE), -1) }.expect("Failed to get page size");
    assert!(pagesize >= 1, "pagesize is always positive");
    let pagesize = pagesize as usize;
    assert!(
        pagesize.is_power_of_two(),
        "pagesize must be a power of two"
    );
    pagesize
});

pub fn safe_process_vm_readv(
    pid: pid_t,
    dest: &mut [u8],
    process_address: *const c_void,
) -> Result<usize, OsError> {
    if dest.len() > *PAGESIZE {
        Err(OsError::new(
            ErrorKind::Other,
            "Reading of buffers bigger than the page size currently not supported",
        ))?
    }

    let base_page = process_address as usize & !(*PAGESIZE - 1);
    let next_page = base_page + *PAGESIZE;

    let base_page_read_size = cmp::min(next_page - process_address as usize, dest.len());
    let next_page_read_size = dest.len() - base_page_read_size;

    let remote_iovec = [
        iovec {
            iov_base: process_address as *mut c_void,
            iov_len: base_page_read_size,
        },
        iovec {
            iov_base: next_page as *mut c_void,
            iov_len: next_page_read_size,
        },
    ];

    let own_iovec = iovec {
        iov_base: dest.as_mut_ptr() as *mut c_void,
        iov_len: dest.len(),
    };

    let read_bytes = unsafe {
        check_ret(
            move || {
                process_vm_readv(
                    pid,
                    &own_iovec as *const iovec,
                    1,
                    &remote_iovec as *const iovec,
                    2,
                    0,
                )
            },
            -1,
        )
    }?;
    Ok(read_bytes as usize)
}

pub unsafe fn check_ret_with_retry<F, T>(mut func: F, error_code: T) -> Result<T, OsError>
where
    F: FnMut() -> T,
    T: Eq + Copy + Debug,
{
    loop {
        return match check_ret(&mut func, error_code) {
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            x => x,
        };
    }
}

pub unsafe fn check_ret<F, T>(func: F, error_code: T) -> Result<T, OsError>
where
    F: FnOnce() -> T,
    T: Eq + Debug,
{
    match func() {
        x if x == error_code => Err(OsError::last_os_error()),
        x => Ok(x),
    }
}

pub enum ForkResult {
    Child,
    Parent { child_pid: pid_t },
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UserRegsAMD64 {
    pub r15: c_ulonglong,
    pub r14: c_ulonglong,
    pub r13: c_ulonglong,
    pub r12: c_ulonglong,
    pub rbp: c_ulonglong,
    pub rbx: c_ulonglong,
    pub r11: c_ulonglong,
    pub r10: c_ulonglong,
    pub r9: c_ulonglong,
    pub r8: c_ulonglong,
    pub rax: c_ulonglong,
    pub rcx: c_ulonglong,
    pub rdx: c_ulonglong,
    pub rsi: c_ulonglong,
    pub rdi: c_ulonglong,
    pub orig_rax: c_ulonglong,
    pub rip: c_ulonglong,
    pub cs: c_ulonglong,
    pub eflags: c_ulonglong,
    pub rsp: c_ulonglong,
    pub ss: c_ulonglong,
    pub fs_base: c_ulonglong,
    pub gs_base: c_ulonglong,
    pub ds: c_ulonglong,
    pub es: c_ulonglong,
    pub fs: c_ulonglong,
    pub gs: c_ulonglong,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UserRegsX86 {
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub eax: u32,
    pub xds: u32,
    pub xes: u32,
    pub xfs: u32,
    pub xgs: u32,
    pub orig_eax: u32,
    pub eip: u32,
    pub xcs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub xss: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union UserRegsUnion {
    pub amd64: UserRegsAMD64,
    pub x86: UserRegsX86,
}

#[derive(Debug)]
pub enum UserRegs {
    AMD64(UserRegsAMD64),
    X86(UserRegsX86),
}
