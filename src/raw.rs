use std::io::Error as OSError;
use std::os::raw::c_int;

extern "C" {
    fn wrapped_stop_self() -> c_int;
}

pub fn stop_self() -> crate::Result<()> {
    let ret = unsafe { wrapped_stop_self() };

    if ret == -1 {
        Err(OSError::last_os_error())?
    }

    Ok(())
}

pub mod ptrace {
    use std::convert::TryInto;
    use std::mem::MaybeUninit;
    use std::{
        os::raw::{c_char, c_int, c_long, c_ulonglong, c_void},
        ptr::null_mut,
    };

    use super::OSError;

    #[repr(C)]
    #[derive(Debug)]
    struct RawWaitPID {
        pid: PTracePID,
        exited: c_char,
        exit_status: c_int,
        terminated_by_signal: c_char,
        termination_signal: c_int,
        is_stopped: c_char,
        stopped_by_syscall: c_char,
        is_error_no_child: c_char,
        signal: c_int,
        event: c_char,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct PtraceSyscallInfoEntry {
        pub nr: u64,
        pub args: [u64; 6],
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct PtraceSyscallInfoExit {
        pub rval: i64,
        pub is_error: u8,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct PtraceSyscallInfoSeccomp {
        pub nr: u64,
        pub args: [u64; 6],
        pub ret_data: u32,
    }

    #[repr(C)]
    pub union PtraceSyscallEventArgs {
        pub entry: PtraceSyscallInfoEntry,
        pub exit: PtraceSyscallInfoExit,
        pub seccomp: PtraceSyscallInfoSeccomp,
    }

    #[repr(C)]
    pub struct PtraceSyscallInfo {
        pub op: u8,
        pub arch: u32,
        pub instruction_pointer: u64,
        pub stack_pointer: u64,
        pub event_args: PtraceSyscallEventArgs,
    }

    #[derive(Debug, Copy, Clone)]
    pub enum PtraceEventTy {
        Fork,
        VFork,
        Clone,
        Exec,
    }

    #[derive(Debug)]
    pub enum WaitPID {
        NoChild,
        Exited {
            pid: PTracePID,
            exit_status: i32,
        },
        Terminated {
            pid: PTracePID,
            termination_signal: i32,
        },
        SysCall {
            pid: PTracePID,
        },
        PTraceEvent {
            pid: PTracePID,
            other_pid: PTracePID,
            ty: PtraceEventTy,
        },
        Signal {
            pid: PTracePID,
            signal: i32,
        },
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
    pub union UserRegs {
        pub amd64: UserRegsAMD64,
        pub x86: UserRegsX86,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct IOVec {
        iov_base: *mut c_void,
        iov_len: usize,
    }

    extern "C" {
        #[must_use]
        fn wrapped_fixed_arg_ptrace(
            request: PTraceRequest,
            pid: PTracePID,
            addr: *mut c_void,
            data: *mut c_void,
        ) -> c_long;

        #[must_use]
        fn wrapped_waitpid(pid: PTracePID, options: c_int) -> RawWaitPID;

        #[must_use]
        fn wrapped_process_vm_readv_string(
            pid: PTracePID,
            dest: *mut c_char,
            length: PTraceMemSize,
            source: *const c_void,
        ) -> PTraceMemSize;
    }

    pub type PTraceRequest = u32;
    pub type PTraceOptionFlag = usize;
    pub type PTracePID = c_int;
    pub type PTraceMemSize = c_long;

    const PTRACE_TRACEME: PTraceRequest = 0;
    const PTRACE_SYSCALL: PTraceRequest = 24;
    const PTRACE_SETOPTIONS: PTraceRequest = 16896;
    const PTRACE_GETEVENTMSG: PTraceRequest = 0x4201;
    const PTRACE_GETREGSET: PTraceRequest = 0x4204;
    const PTRACE_GETSYSCALLINFO: PTraceRequest = 0x420e;

    const PTRACE_O_TRACESYSGOOD: PTraceOptionFlag = 0x00000001;
    const PTRACE_O_TRACEFORK: PTraceOptionFlag = 0x00000002;
    const PTRACE_O_TRACEVFORK: PTraceOptionFlag = 0x00000004;
    const PTRACE_O_TRACECLONE: PTraceOptionFlag = 0x00000008;
    const PTRACE_O_TRACEEXEC: PTraceOptionFlag = 0x00000010;
    const PTRACE_NT_PRSTATUS: PTraceOptionFlag = 1;
    const WAITPID_WAITALL: c_int = 0x40000000;

    fn ptrace_to_result(res: c_long) -> crate::Result<()> {
        match res {
            -1 => Err(OSError::last_os_error().into()),
            _ => Ok(()),
        }
    }

    pub fn trace_me() -> crate::Result<()> {
        unsafe {
            ptrace_to_result(wrapped_fixed_arg_ptrace(
                PTRACE_TRACEME,
                0,
                null_mut(),
                null_mut(),
            ))
        }
    }

    pub fn trace_syscall_with_signal_delivery(pid: PTracePID, signal: i32) -> crate::Result<()> {
        unsafe {
            ptrace_to_result(wrapped_fixed_arg_ptrace(
                PTRACE_SYSCALL,
                pid,
                null_mut(),
                signal as *mut c_void,
            ))
        }
    }

    pub fn set_trace_syscall_option(pid: PTracePID) -> crate::Result<()> {
        let options = PTRACE_O_TRACESYSGOOD
            | PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEEXEC;

        let ret = unsafe {
            wrapped_fixed_arg_ptrace(PTRACE_SETOPTIONS, pid, null_mut(), options as *mut c_void)
        };

        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(())
        }
    }

    pub fn wait_all() -> crate::Result<WaitPID> {
        unsafe { wrapped_waitpid(-1, WAITPID_WAITALL) }.into()
    }

    pub fn wait_for(pid: PTracePID) -> crate::Result<WaitPID> {
        unsafe { wrapped_waitpid(pid, 0) }.into()
    }

    pub fn get_syscall_info_fast(pid: PTracePID) -> Result<PtraceSyscallInfo, OSError> {
        let mut info = MaybeUninit::<PtraceSyscallInfo>::uninit();
        let size = std::mem::size_of_val(&info);
        let ret = unsafe {
            wrapped_fixed_arg_ptrace(
                PTRACE_GETSYSCALLINFO,
                pid,
                size as *mut c_void,
                info.as_mut_ptr() as *mut c_void,
            )
        };
        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(unsafe { info.assume_init() })
        }
    }

    pub fn get_process_registers(pid: PTracePID) -> Result<(usize, UserRegs), OSError> {
        let mut regs = MaybeUninit::<UserRegs>::uninit();
        let size = std::mem::size_of_val(&regs);

        let mut iovec = IOVec {
            iov_base: regs.as_mut_ptr() as *mut c_void,
            iov_len: size,
        };
        let ret = unsafe {
            wrapped_fixed_arg_ptrace(
                PTRACE_GETREGSET,
                pid,
                PTRACE_NT_PRSTATUS as *mut c_void,
                &mut iovec as *mut IOVec as *mut c_void,
            )
        };

        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            let regs = unsafe { regs.assume_init() };
            Ok((iovec.iov_len, regs))
        }
    }

    pub fn read_from_process(pid: PTracePID, dest: &mut [u8], source: u64) -> crate::Result<&[u8]> {
        let ret = unsafe {
            wrapped_process_vm_readv_string(
                pid,
                dest.as_mut_ptr() as *mut c_char,
                dest.len().try_into()?,
                source as *mut c_void,
            )
        };

        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(&dest[..ret as usize])
        }
    }

    fn get_event_msg(pid: PTracePID) -> crate::Result<u64> {
        let mut res = 0;
        let ret = unsafe {
            wrapped_fixed_arg_ptrace(
                PTRACE_GETEVENTMSG,
                pid,
                null_mut(),
                &mut res as *mut u64 as *mut c_void,
            )
        };
        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(res)
        }
    }

    impl From<RawWaitPID> for crate::Result<WaitPID> {
        fn from(raw: RawWaitPID) -> Self {
            match raw {
                RawWaitPID {
                    pid: -1,
                    is_error_no_child: 1,
                    ..
                } => Ok(WaitPID::NoChild),
                RawWaitPID { pid: -1, .. } => Err(OSError::last_os_error())?,
                RawWaitPID {
                    exited: 1,
                    pid,
                    exit_status,
                    ..
                } => Ok(WaitPID::Exited { pid, exit_status }),
                x @ RawWaitPID { is_stopped: 0, .. } => Err(format!(
                    "Process {} not stopped in waitpid(): {:#?}",
                    x.pid, x
                ))?,
                RawWaitPID {
                    terminated_by_signal: 1,
                    pid,
                    termination_signal,
                    ..
                } => Ok(WaitPID::Terminated {
                    pid,
                    termination_signal,
                }),
                RawWaitPID {
                    stopped_by_syscall: 1,
                    pid,
                    ..
                } => Ok(WaitPID::SysCall { pid }),
                RawWaitPID {
                    pid, event, signal, ..
                } if event > 0 => {
                    let other_pid = get_event_msg(pid)? as PTracePID;
                    let ty = match event {
                        0 => return Ok(WaitPID::Signal { pid, signal }),
                        1 => PtraceEventTy::Fork,
                        2 => PtraceEventTy::VFork,
                        3 => PtraceEventTy::Clone,
                        4 => PtraceEventTy::Exec,
                        _ => Err(format!(
                            "Could not decode event {} of process {}",
                            event, pid
                        ))?,
                    };
                    Ok(WaitPID::PTraceEvent { pid, other_pid, ty })
                }
                RawWaitPID { pid, signal, .. } => Ok(WaitPID::Signal { pid, signal }),
            }
        }
    }
}
