pub mod ptrace {
    use std::{
        io::{Error as OSError},
        os::{
            raw::{
                c_char,
                c_int,
                c_long,
                c_void,
            }
        },
        ptr::null_mut,
    };
    use std::convert::TryInto;
    use std::mem::MaybeUninit;

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
    }

    extern "C" {
        #[must_use]
        fn wrapped_fixed_arg_ptrace(request: PTraceRequest, pid: PTracePID, addr: *mut c_void, data: *mut c_void) -> c_long;

        #[must_use]
        fn wrapped_waitpid(pid: PTracePID, options: c_int) -> RawWaitPID;

        #[must_use]
        fn wrapped_process_vm_readv_string(pid: PTracePID, dest: *mut c_char, length: PTraceMemSize, source: *const c_void) -> PTraceMemSize;
    }

    pub type PTraceRequest = u32;
    pub type PTraceOptionFlag = usize;
    pub type PTracePID = c_int;
    pub type PTraceMemSize = c_long;

    const PTRACE_TRACEME: PTraceRequest = 0;
    const PTRACE_SYSCALL: PTraceRequest = 24;
    const PTRACE_SETOPTIONS: PTraceRequest = 16896;
    const PTRACE_DETACH: PTraceRequest = 17;
    const PTRACE_O_TRACESYSGOOD: PTraceOptionFlag = 1;
    const WAITPID_WAITALL: c_int = 0x40000000;

    pub fn trace_me() -> crate::Result<()> {
        let ret = unsafe {
            wrapped_fixed_arg_ptrace(PTRACE_TRACEME, 0, null_mut(), null_mut())
        };

        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(())
        }
    }

    pub fn trace_syscall(pid: PTracePID) -> crate::Result<()> {
        let ret = unsafe {
            wrapped_fixed_arg_ptrace(PTRACE_SYSCALL, pid, null_mut(), null_mut())
        };

        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(())
        }
    }

    pub fn set_trace_syscall_option(pid: PTracePID) -> crate::Result<()> {
        let options = PTRACE_O_TRACESYSGOOD;

        let ret = unsafe {
            wrapped_fixed_arg_ptrace(PTRACE_SETOPTIONS, pid, null_mut(), options as *mut c_void)
        };

        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(())
        }
    }

    pub fn detach(pid: PTracePID) -> crate::Result<()> {
        let ret = unsafe {
            wrapped_fixed_arg_ptrace(PTRACE_DETACH, pid, null_mut(), null_mut())
        };

        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(())
        }
    }

    pub fn wait_all() -> crate::Result<WaitPID> {
        unsafe {
            wrapped_waitpid(-1, WAITPID_WAITALL)
        }.into()
    }

    pub fn wait_for(pid: PTracePID) -> crate::Result<WaitPID> {
        unsafe {
            wrapped_waitpid(pid, 0)
        }.into()
    }

    pub fn get_syscall_info(pid: PTracePID) -> crate::Result<PtraceSyscallInfo> {
        let mut info = MaybeUninit::<PtraceSyscallInfo>::uninit();
        let size = std::mem::size_of_val(&info);
        let ret = unsafe {
            wrapped_fixed_arg_ptrace(0x420e, pid, size as *mut c_void, info.as_mut_ptr() as *mut c_void)
        };
        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(unsafe { info.assume_init() })
        }
    }

    pub fn read_from_process(pid: PTracePID, dest: &mut [u8], source: u64) -> crate::Result<&[u8]> {
        let ret = unsafe {
            wrapped_process_vm_readv_string(
                pid,
                dest.as_mut_ptr() as *mut c_char,
                dest.len().try_into()?,
                source as *mut c_void
            )
        };

        if ret == -1 {
            Err(OSError::last_os_error().into())
        } else {
            Ok(&dest[..ret as usize])
        }
    }


    impl From<RawWaitPID> for crate::Result<WaitPID> {
        fn from(raw: RawWaitPID) -> Self {
            match raw {
                RawWaitPID { pid: -1, is_error_no_child: 1, .. } => Ok(WaitPID::NoChild),
                RawWaitPID { pid: -1, .. } => Err(OSError::last_os_error())?,
                RawWaitPID { is_stopped: 0, pid, .. } => Err(format!("Process {} not stopped in waitpid()", pid))?,
                RawWaitPID { exited: 1, pid, exit_status, .. } => Ok(WaitPID::Exited {
                    pid,
                    exit_status,
                }),
                RawWaitPID { terminated_by_signal: 1, pid, termination_signal, .. } => Ok(WaitPID::Terminated {
                    pid,
                    termination_signal,
                }),
                RawWaitPID { pid, .. } => Ok(WaitPID::SysCall { pid }),
            }
        }
    }
}
