#![allow(unused_variables)]

use super::syscall_args::FromStoppedProcess;
use crate::{OsError, StoppedProcess};
use std::ffi::OsString;
use std::os::raw::c_void;

#[derive(Debug, Clone)]
pub struct Accept {}

#[derive(Debug, Clone)]
pub struct Accept4 {}

#[derive(Debug, Clone)]
pub struct Access {}

#[derive(Debug, Clone)]
pub struct Acct {}

#[derive(Debug, Clone)]
pub struct AddKey {}

#[derive(Debug, Clone)]
pub struct Adjtimex {}

#[derive(Debug, Clone)]
pub struct AdjtimexTime32 {}

#[derive(Debug, Clone)]
pub struct Alarm {}

#[derive(Debug, Clone)]
pub struct AlphaPipe {}

#[derive(Debug, Clone)]
pub struct ArcGettls {}

#[derive(Debug, Clone)]
pub struct ArcSettls {}

#[derive(Debug, Clone)]
pub struct ArcUsrCmpxchg {}

#[derive(Debug, Clone)]
pub struct Arch32Ftruncate64 {}

#[derive(Debug, Clone)]
pub struct Arch32Llseek {}

#[derive(Debug, Clone)]
pub struct Arch32Personality {}

#[derive(Debug, Clone)]
pub struct Arch32Pread {}

#[derive(Debug, Clone)]
pub struct Arch32Pwrite {}

#[derive(Debug, Clone)]
pub struct Arch32Sigaction {}

#[derive(Debug, Clone)]
pub struct Arch32Truncate64 {}

#[derive(Debug, Clone)]
pub struct Arch64Mremap {}

#[derive(Debug, Clone)]
pub struct Arch64Munmap {}

#[derive(Debug, Clone)]
pub struct ArchPrctl {}

#[derive(Debug, Clone)]
pub struct Arm64Personality {}

#[derive(Debug, Clone)]
pub struct Bdflush {}

#[derive(Debug, Clone)]
pub struct Bind {}

#[derive(Debug, Clone)]
pub struct Bpf {}

#[derive(Debug, Clone)]
pub struct Brk {}

#[derive(Debug, Clone)]
pub struct Cachectl {}

#[derive(Debug, Clone)]
pub struct Cacheflush {}

#[derive(Debug, Clone)]
pub struct Capget {}

#[derive(Debug, Clone)]
pub struct Capset {}

#[derive(Debug, Clone)]
pub struct Chdir {}

#[derive(Debug, Clone)]
pub struct Chmod {}

#[derive(Debug, Clone)]
pub struct Chown {}

#[derive(Debug, Clone)]
pub struct Chown16 {}

#[derive(Debug, Clone)]
pub struct Chroot {}

#[derive(Debug, Clone)]
pub struct ClockAdjtime {}

#[derive(Debug, Clone)]
pub struct ClockAdjtime32 {}

#[derive(Debug, Clone)]
pub struct ClockGetres {}

#[derive(Debug, Clone)]
pub struct ClockGetresTime32 {}

#[derive(Debug, Clone)]
pub struct ClockGettime {}

#[derive(Debug, Clone)]
pub struct ClockGettime32 {}

#[derive(Debug, Clone)]
pub struct ClockNanosleep {}

#[derive(Debug, Clone)]
pub struct ClockNanosleepTime32 {}

#[derive(Debug, Clone)]
pub struct ClockSettime {}

#[derive(Debug, Clone)]
pub struct ClockSettime32 {}

#[derive(Debug, Clone)]
pub struct Clone {}

#[derive(Debug, Clone)]
pub struct Clone3 {}

#[derive(Debug, Clone)]
pub struct Close {}

#[derive(Debug, Clone)]
pub struct Connect {}

#[derive(Debug, Clone)]
pub struct CopyFileRange {}

#[derive(Debug, Clone)]
pub struct Creat {}

#[derive(Debug, Clone)]
pub struct CskyFadvise6464 {}

#[derive(Debug, Clone)]
pub struct DebugSetcontext {}

#[derive(Debug, Clone)]
pub struct DeleteModule {}

#[derive(Debug, Clone)]
pub struct Dup {}

#[derive(Debug, Clone)]
pub struct Dup2 {}

#[derive(Debug, Clone)]
pub struct Dup3 {}

#[derive(Debug, Clone)]
pub struct EpollCreate {}

#[derive(Debug, Clone)]
pub struct EpollCreate1 {}

#[derive(Debug, Clone)]
pub struct EpollCtl {}

#[derive(Debug, Clone)]
pub struct EpollPwait {}

#[derive(Debug, Clone)]
pub struct EpollWait {}

#[derive(Debug, Clone)]
pub struct Eventfd {}

#[derive(Debug, Clone)]
pub struct Eventfd2 {}

#[derive(Debug, Clone)]
pub struct Execve {
    filename: OsString,
    argv: Vec<OsString>,
    envp: Vec<OsString>,
}

#[derive(Debug, Clone)]
pub struct Execveat {}

#[derive(Debug, Clone)]
pub struct Exit {}

#[derive(Debug, Clone)]
pub struct ExitGroup {}

#[derive(Debug, Clone)]
pub struct Faccessat {}

#[derive(Debug, Clone)]
pub struct Fadvise64 {}

#[derive(Debug, Clone)]
pub struct Fadvise6464 {}

#[derive(Debug, Clone)]
pub struct Fadvise6464Wrapper {}

#[derive(Debug, Clone)]
pub struct Fallocate {}

#[derive(Debug, Clone)]
pub struct FanotifyInit {}

#[derive(Debug, Clone)]
pub struct FanotifyMark {}

#[derive(Debug, Clone)]
pub struct Fchdir {}

#[derive(Debug, Clone)]
pub struct Fchmod {}

#[derive(Debug, Clone)]
pub struct Fchmodat {}

#[derive(Debug, Clone)]
pub struct Fchown {}

#[derive(Debug, Clone)]
pub struct Fchown16 {}

#[derive(Debug, Clone)]
pub struct Fchownat {}

#[derive(Debug, Clone)]
pub struct Fcntl {}

#[derive(Debug, Clone)]
pub struct Fcntl64 {}

#[derive(Debug, Clone)]
pub struct Fdatasync {}

#[derive(Debug, Clone)]
pub struct Fgetxattr {}

#[derive(Debug, Clone)]
pub struct FinitModule {}

#[derive(Debug, Clone)]
pub struct Flistxattr {}

#[derive(Debug, Clone)]
pub struct Flock {}

#[derive(Debug, Clone)]
pub struct Fork {}

#[derive(Debug, Clone)]
pub struct FpUdfiexCrtl {}

#[derive(Debug, Clone)]
pub struct Fremovexattr {}

#[derive(Debug, Clone)]
pub struct Fsconfig {}

#[derive(Debug, Clone)]
pub struct Fsetxattr {}

#[derive(Debug, Clone)]
pub struct Fsmount {}

#[derive(Debug, Clone)]
pub struct Fsopen {}

#[derive(Debug, Clone)]
pub struct Fspick {}

#[derive(Debug, Clone)]
pub struct Fstat {}

#[derive(Debug, Clone)]
pub struct Fstat64 {}

#[derive(Debug, Clone)]
pub struct Fstatat64 {}

#[derive(Debug, Clone)]
pub struct Fstatfs {}

#[derive(Debug, Clone)]
pub struct Fstatfs64 {}

#[derive(Debug, Clone)]
pub struct Fsync {}

#[derive(Debug, Clone)]
pub struct Ftruncate {}

#[derive(Debug, Clone)]
pub struct Ftruncate64 {}

#[derive(Debug, Clone)]
pub struct Futex {}

#[derive(Debug, Clone)]
pub struct FutexTime32 {}

#[derive(Debug, Clone)]
pub struct Futimesat {}

#[derive(Debug, Clone)]
pub struct FutimesatTime32 {}

#[derive(Debug, Clone)]
pub struct GetMempolicy {}

#[derive(Debug, Clone)]
pub struct GetRobustList {}

#[derive(Debug, Clone)]
pub struct GetThreadArea {}

#[derive(Debug, Clone)]
pub struct Getcpu {}

#[derive(Debug, Clone)]
pub struct Getcwd {}

#[derive(Debug, Clone)]
pub struct Getdents {}

#[derive(Debug, Clone)]
pub struct Getdents64 {}

#[derive(Debug, Clone)]
pub struct Getdomainname {}

#[derive(Debug, Clone)]
pub struct Getdtablesize {}

#[derive(Debug, Clone)]
pub struct Getegid {}

#[derive(Debug, Clone)]
pub struct Getegid16 {}

#[derive(Debug, Clone)]
pub struct Geteuid {}

#[derive(Debug, Clone)]
pub struct Geteuid16 {}

#[derive(Debug, Clone)]
pub struct Getgid {}

#[derive(Debug, Clone)]
pub struct Getgid16 {}

#[derive(Debug, Clone)]
pub struct Getgroups {}

#[derive(Debug, Clone)]
pub struct Getgroups16 {}

#[derive(Debug, Clone)]
pub struct Gethostname {}

#[derive(Debug, Clone)]
pub struct Getitimer {}

#[derive(Debug, Clone)]
pub struct Getpagesize {}

#[derive(Debug, Clone)]
pub struct Getpeername {}

#[derive(Debug, Clone)]
pub struct Getpgid {}

#[derive(Debug, Clone)]
pub struct Getpgrp {}

#[derive(Debug, Clone)]
pub struct Getpid {}

#[derive(Debug, Clone)]
pub struct Getppid {}

#[derive(Debug, Clone)]
pub struct Getpriority {}

#[derive(Debug, Clone)]
pub struct Getrandom {}

#[derive(Debug, Clone)]
pub struct Getresgid {}

#[derive(Debug, Clone)]
pub struct Getresgid16 {}

#[derive(Debug, Clone)]
pub struct Getresuid {}

#[derive(Debug, Clone)]
pub struct Getresuid16 {}

#[derive(Debug, Clone)]
pub struct Getrlimit {}

#[derive(Debug, Clone)]
pub struct Getrusage {}

#[derive(Debug, Clone)]
pub struct Getsid {}

#[derive(Debug, Clone)]
pub struct Getsockname {}

#[derive(Debug, Clone)]
pub struct Getsockopt {}

#[derive(Debug, Clone)]
pub struct Gettid {}

#[derive(Debug, Clone)]
pub struct Gettimeofday {}

#[derive(Debug, Clone)]
pub struct Getuid {}

#[derive(Debug, Clone)]
pub struct Getuid16 {}

#[derive(Debug, Clone)]
pub struct Getxattr {}

#[derive(Debug, Clone)]
pub struct Getxgid {}

#[derive(Debug, Clone)]
pub struct Getxpid {}

#[derive(Debug, Clone)]
pub struct Getxuid {}

#[derive(Debug, Clone)]
pub struct InitModule {}

#[derive(Debug, Clone)]
pub struct InotifyAddWatch {}

#[derive(Debug, Clone)]
pub struct InotifyInit {}

#[derive(Debug, Clone)]
pub struct InotifyInit1 {}

#[derive(Debug, Clone)]
pub struct InotifyRmWatch {}

#[derive(Debug, Clone)]
pub struct IoCancel {}

#[derive(Debug, Clone)]
pub struct IoDestroy {}

#[derive(Debug, Clone)]
pub struct IoGetevents {}

#[derive(Debug, Clone)]
pub struct IoGeteventsTime32 {}

#[derive(Debug, Clone)]
pub struct IoPgetevents {}

#[derive(Debug, Clone)]
pub struct IoPgeteventsTime32 {}

#[derive(Debug, Clone)]
pub struct IoSetup {}

#[derive(Debug, Clone)]
pub struct IoSubmit {}

#[derive(Debug, Clone)]
pub struct IoUringEnter {}

#[derive(Debug, Clone)]
pub struct IoUringRegister {}

#[derive(Debug, Clone)]
pub struct IoUringSetup {}

#[derive(Debug, Clone)]
pub struct Ioctl {}

#[derive(Debug, Clone)]
pub struct Ioperm {}

#[derive(Debug, Clone)]
pub struct Iopl {}

#[derive(Debug, Clone)]
pub struct IoprioGet {}

#[derive(Debug, Clone)]
pub struct IoprioSet {}

#[derive(Debug, Clone)]
pub struct Ipc {}

#[derive(Debug, Clone)]
pub struct Kcmp {}

#[derive(Debug, Clone)]
pub struct KernFeatures {}

#[derive(Debug, Clone)]
pub struct KexecFileLoad {}

#[derive(Debug, Clone)]
pub struct KexecLoad {}

#[derive(Debug, Clone)]
pub struct Keyctl {}

#[derive(Debug, Clone)]
pub struct Kill {}

#[derive(Debug, Clone)]
pub struct Lchown {}

#[derive(Debug, Clone)]
pub struct Lchown16 {}

#[derive(Debug, Clone)]
pub struct Lgetxattr {}

#[derive(Debug, Clone)]
pub struct Link {}

#[derive(Debug, Clone)]
pub struct Linkat {}

#[derive(Debug, Clone)]
pub struct Listen {}

#[derive(Debug, Clone)]
pub struct Listxattr {}

#[derive(Debug, Clone)]
pub struct Llistxattr {}

#[derive(Debug, Clone)]
pub struct Llseek {}

#[derive(Debug, Clone)]
pub struct LookupDcookie {}

#[derive(Debug, Clone)]
pub struct Lremovexattr {}

#[derive(Debug, Clone)]
pub struct Lseek {}

#[derive(Debug, Clone)]
pub struct Lsetxattr {}

#[derive(Debug, Clone)]
pub struct Lstat {}

#[derive(Debug, Clone)]
pub struct Lstat64 {}

#[derive(Debug, Clone)]
pub struct Madvise {}

#[derive(Debug, Clone)]
pub struct Mbind {}

#[derive(Debug, Clone)]
pub struct Membarrier {}

#[derive(Debug, Clone)]
pub struct MemfdCreate {}

#[derive(Debug, Clone)]
pub struct MemoryOrdering {}

#[derive(Debug, Clone)]
pub struct MigratePages {}

#[derive(Debug, Clone)]
pub struct Mincore {}

#[derive(Debug, Clone)]
pub struct MipsMmap {}

#[derive(Debug, Clone)]
pub struct MipsMmap2 {}

#[derive(Debug, Clone)]
pub struct Mkdir {}

#[derive(Debug, Clone)]
pub struct Mkdirat {}

#[derive(Debug, Clone)]
pub struct Mknod {}

#[derive(Debug, Clone)]
pub struct Mknodat {}

#[derive(Debug, Clone)]
pub struct Mlock {}

#[derive(Debug, Clone)]
pub struct Mlock2 {}

#[derive(Debug, Clone)]
pub struct Mlockall {}

#[derive(Debug, Clone)]
pub struct Mmap {}

#[derive(Debug, Clone)]
pub struct Mmap2 {}

#[derive(Debug, Clone)]
pub struct MmapPgoff {}

#[derive(Debug, Clone)]
pub struct ModifyLdt {}

#[derive(Debug, Clone)]
pub struct Mount {}

#[derive(Debug, Clone)]
pub struct MoveMount {}

#[derive(Debug, Clone)]
pub struct MovePages {}

#[derive(Debug, Clone)]
pub struct Mprotect {}

#[derive(Debug, Clone)]
pub struct MqGetsetattr {}

#[derive(Debug, Clone)]
pub struct MqNotify {}

#[derive(Debug, Clone)]
pub struct MqOpen {}

#[derive(Debug, Clone)]
pub struct MqTimedreceive {}

#[derive(Debug, Clone)]
pub struct MqTimedreceiveTime32 {}

#[derive(Debug, Clone)]
pub struct MqTimedsend {}

#[derive(Debug, Clone)]
pub struct MqTimedsendTime32 {}

#[derive(Debug, Clone)]
pub struct MqUnlink {}

#[derive(Debug, Clone)]
pub struct Mremap {}

#[derive(Debug, Clone)]
pub struct Msgctl {}

#[derive(Debug, Clone)]
pub struct Msgget {}

#[derive(Debug, Clone)]
pub struct Msgrcv {}

#[derive(Debug, Clone)]
pub struct Msgsnd {}

#[derive(Debug, Clone)]
pub struct Msync {}

#[derive(Debug, Clone)]
pub struct Munlock {}

#[derive(Debug, Clone)]
pub struct Munlockall {}

#[derive(Debug, Clone)]
pub struct Munmap {}

#[derive(Debug, Clone)]
pub struct NameToHandleAt {}

#[derive(Debug, Clone)]
pub struct Nanosleep {}

#[derive(Debug, Clone)]
pub struct NanosleepTime32 {}

#[derive(Debug, Clone)]
pub struct Newfstat {}

#[derive(Debug, Clone)]
pub struct Newfstatat {}

#[derive(Debug, Clone)]
pub struct Newlstat {}

#[derive(Debug, Clone)]
pub struct Newstat {}

#[derive(Debug, Clone)]
pub struct Newuname {}

#[derive(Debug, Clone)]
pub struct NiSyscall {}

#[derive(Debug, Clone)]
pub struct Nice {}

#[derive(Debug, Clone)]
pub struct NisSyscall {}

#[derive(Debug, Clone)]
pub struct OldAdjtimex {}

#[derive(Debug, Clone)]
pub struct OldGetrlimit {}

#[derive(Debug, Clone)]
pub struct OldMmap {}

#[derive(Debug, Clone)]
pub struct OldMsgctl {}

#[derive(Debug, Clone)]
pub struct OldReaddir {}

#[derive(Debug, Clone)]
pub struct OldSelect {}

#[derive(Debug, Clone)]
pub struct OldSemctl {}

#[derive(Debug, Clone)]
pub struct OldShmctl {}

#[derive(Debug, Clone)]
pub struct Oldumount {}

#[derive(Debug, Clone)]
pub struct Olduname {}

#[derive(Debug, Clone)]
pub struct Open {}

#[derive(Debug, Clone)]
pub struct OpenByHandleAt {}

#[derive(Debug, Clone)]
pub struct OpenTree {}

#[derive(Debug, Clone)]
pub struct Openat {}

#[derive(Debug, Clone)]
pub struct Openat2 {}

#[derive(Debug, Clone)]
pub struct OsfBrk {}

#[derive(Debug, Clone)]
pub struct OsfFstat {}

#[derive(Debug, Clone)]
pub struct OsfFstatfs {}

#[derive(Debug, Clone)]
pub struct OsfFstatfs64 {}

#[derive(Debug, Clone)]
pub struct OsfGetdirentries {}

#[derive(Debug, Clone)]
pub struct OsfGetdomainname {}

#[derive(Debug, Clone)]
pub struct OsfGetpriority {}

#[derive(Debug, Clone)]
pub struct OsfGetrusage {}

#[derive(Debug, Clone)]
pub struct OsfGetsysinfo {}

#[derive(Debug, Clone)]
pub struct OsfGettimeofday {}

#[derive(Debug, Clone)]
pub struct OsfLstat {}

#[derive(Debug, Clone)]
pub struct OsfMmap {}

#[derive(Debug, Clone)]
pub struct OsfMount {}

#[derive(Debug, Clone)]
pub struct OsfProplistSyscall {}

#[derive(Debug, Clone)]
pub struct OsfReadv {}

#[derive(Debug, Clone)]
pub struct OsfSelect {}

#[derive(Debug, Clone)]
pub struct OsfSetProgramAttributes {}

#[derive(Debug, Clone)]
pub struct OsfSetsysinfo {}

#[derive(Debug, Clone)]
pub struct OsfSettimeofday {}

#[derive(Debug, Clone)]
pub struct OsfSigaction {}

#[derive(Debug, Clone)]
pub struct OsfSigprocmask {}

#[derive(Debug, Clone)]
pub struct OsfSigstack {}

#[derive(Debug, Clone)]
pub struct OsfStat {}

#[derive(Debug, Clone)]
pub struct OsfStatfs {}

#[derive(Debug, Clone)]
pub struct OsfStatfs64 {}

#[derive(Debug, Clone)]
pub struct OsfSysinfo {}

#[derive(Debug, Clone)]
pub struct OsfUsleepThread {}

#[derive(Debug, Clone)]
pub struct OsfUtimes {}

#[derive(Debug, Clone)]
pub struct OsfUtsname {}

#[derive(Debug, Clone)]
pub struct OsfWait4 {}

#[derive(Debug, Clone)]
pub struct OsfWritev {}

#[derive(Debug, Clone)]
pub struct Pause {}

#[derive(Debug, Clone)]
pub struct PciconfigIobase {}

#[derive(Debug, Clone)]
pub struct PciconfigRead {}

#[derive(Debug, Clone)]
pub struct PciconfigWrite {}

#[derive(Debug, Clone)]
pub struct PerfEventOpen {}

#[derive(Debug, Clone)]
pub struct Personality {}

#[derive(Debug, Clone)]
pub struct PidfdGetfd {}

#[derive(Debug, Clone)]
pub struct PidfdOpen {}

#[derive(Debug, Clone)]
pub struct PidfdSendSignal {}

#[derive(Debug, Clone)]
pub struct Pipe {}

#[derive(Debug, Clone)]
pub struct Pipe2 {}

#[derive(Debug, Clone)]
pub struct PivotRoot {}

#[derive(Debug, Clone)]
pub struct PkeyAlloc {}

#[derive(Debug, Clone)]
pub struct PkeyFree {}

#[derive(Debug, Clone)]
pub struct PkeyMprotect {}

#[derive(Debug, Clone)]
pub struct Poll {}

#[derive(Debug, Clone)]
pub struct Ppoll {}

#[derive(Debug, Clone)]
pub struct PpollTime32 {}

#[derive(Debug, Clone)]
pub struct Prctl {}

#[derive(Debug, Clone)]
pub struct Pread64 {}

#[derive(Debug, Clone)]
pub struct Preadv {}

#[derive(Debug, Clone)]
pub struct Preadv2 {}

#[derive(Debug, Clone)]
pub struct Prlimit64 {}

#[derive(Debug, Clone)]
pub struct ProcessVmReadv {}

#[derive(Debug, Clone)]
pub struct ProcessVmWritev {}

#[derive(Debug, Clone)]
pub struct Pselect6 {}

#[derive(Debug, Clone)]
pub struct Pselect6Time32 {}

#[derive(Debug, Clone)]
pub struct Ptrace {}

#[derive(Debug, Clone)]
pub struct Pwrite64 {}

#[derive(Debug, Clone)]
pub struct Pwritev {}

#[derive(Debug, Clone)]
pub struct Pwritev2 {}

#[derive(Debug, Clone)]
pub struct Quotactl {}

#[derive(Debug, Clone)]
pub struct Read {}

#[derive(Debug, Clone)]
pub struct Readahead {}

#[derive(Debug, Clone)]
pub struct Readlink {}

#[derive(Debug, Clone)]
pub struct Readlinkat {}

#[derive(Debug, Clone)]
pub struct Readv {}

#[derive(Debug, Clone)]
pub struct Reboot {}

#[derive(Debug, Clone)]
pub struct Recv {}

#[derive(Debug, Clone)]
pub struct Recvfrom {}

#[derive(Debug, Clone)]
pub struct Recvmmsg {}

#[derive(Debug, Clone)]
pub struct RecvmmsgTime32 {}

#[derive(Debug, Clone)]
pub struct Recvmsg {}

#[derive(Debug, Clone)]
pub struct RemapFilePages {}

#[derive(Debug, Clone)]
pub struct Removexattr {}

#[derive(Debug, Clone)]
pub struct Rename {}

#[derive(Debug, Clone)]
pub struct Renameat {}

#[derive(Debug, Clone)]
pub struct Renameat2 {}

#[derive(Debug, Clone)]
pub struct RequestKey {}

#[derive(Debug, Clone)]
pub struct RestartSyscall {}

#[derive(Debug, Clone)]
pub struct RiscvFlushIcache {}

#[derive(Debug, Clone)]
pub struct Rmdir {}

#[derive(Debug, Clone)]
pub struct Rseq {}

#[derive(Debug, Clone)]
pub struct RtSigaction {}

#[derive(Debug, Clone)]
pub struct RtSigpending {}

#[derive(Debug, Clone)]
pub struct RtSigprocmask {}

#[derive(Debug, Clone)]
pub struct RtSigqueueinfo {}

#[derive(Debug, Clone)]
pub struct RtSigreturn {}

#[derive(Debug, Clone)]
pub struct RtSigsuspend {}

#[derive(Debug, Clone)]
pub struct RtSigtimedwait {}

#[derive(Debug, Clone)]
pub struct RtSigtimedwaitTime32 {}

#[derive(Debug, Clone)]
pub struct RtTgsigqueueinfo {}

#[derive(Debug, Clone)]
pub struct Rtas {}

#[derive(Debug, Clone)]
pub struct S390GuardedStorage {}

#[derive(Debug, Clone)]
pub struct S390Ipc {}

#[derive(Debug, Clone)]
pub struct S390PciMmioRead {}

#[derive(Debug, Clone)]
pub struct S390PciMmioWrite {}

#[derive(Debug, Clone)]
pub struct S390Personality {}

#[derive(Debug, Clone)]
pub struct S390RuntimeInstr {}

#[derive(Debug, Clone)]
pub struct S390Sthyi {}

#[derive(Debug, Clone)]
pub struct SchedGetPriorityMax {}

#[derive(Debug, Clone)]
pub struct SchedGetPriorityMin {}

#[derive(Debug, Clone)]
pub struct SchedGetaffinity {}

#[derive(Debug, Clone)]
pub struct SchedGetattr {}

#[derive(Debug, Clone)]
pub struct SchedGetparam {}

#[derive(Debug, Clone)]
pub struct SchedGetscheduler {}

#[derive(Debug, Clone)]
pub struct SchedRrGetInterval {}

#[derive(Debug, Clone)]
pub struct SchedRrGetIntervalTime32 {}

#[derive(Debug, Clone)]
pub struct SchedSetaffinity {}

#[derive(Debug, Clone)]
pub struct SchedSetattr {}

#[derive(Debug, Clone)]
pub struct SchedSetparam {}

#[derive(Debug, Clone)]
pub struct SchedSetscheduler {}

#[derive(Debug, Clone)]
pub struct SchedYield {}

#[derive(Debug, Clone)]
pub struct Seccomp {}

#[derive(Debug, Clone)]
pub struct Select {}

#[derive(Debug, Clone)]
pub struct Semctl {}

#[derive(Debug, Clone)]
pub struct Semget {}

#[derive(Debug, Clone)]
pub struct Semop {}

#[derive(Debug, Clone)]
pub struct Semtimedop {}

#[derive(Debug, Clone)]
pub struct SemtimedopTime32 {}

#[derive(Debug, Clone)]
pub struct Send {}

#[derive(Debug, Clone)]
pub struct Sendfile {}

#[derive(Debug, Clone)]
pub struct Sendfile64 {}

#[derive(Debug, Clone)]
pub struct Sendmmsg {}

#[derive(Debug, Clone)]
pub struct Sendmsg {}

#[derive(Debug, Clone)]
pub struct Sendto {}

#[derive(Debug, Clone)]
pub struct SetMempolicy {}

#[derive(Debug, Clone)]
pub struct SetRobustList {}

#[derive(Debug, Clone)]
pub struct SetThreadArea {}

#[derive(Debug, Clone)]
pub struct SetTidAddress {}

#[derive(Debug, Clone)]
pub struct Setdomainname {}

#[derive(Debug, Clone)]
pub struct Setfsgid {}

#[derive(Debug, Clone)]
pub struct Setfsgid16 {}

#[derive(Debug, Clone)]
pub struct Setfsuid {}

#[derive(Debug, Clone)]
pub struct Setfsuid16 {}

#[derive(Debug, Clone)]
pub struct Setgid {}

#[derive(Debug, Clone)]
pub struct Setgid16 {}

#[derive(Debug, Clone)]
pub struct Setgroups {}

#[derive(Debug, Clone)]
pub struct Setgroups16 {}

#[derive(Debug, Clone)]
pub struct Sethae {}

#[derive(Debug, Clone)]
pub struct Sethostname {}

#[derive(Debug, Clone)]
pub struct Setitimer {}

#[derive(Debug, Clone)]
pub struct Setns {}

#[derive(Debug, Clone)]
pub struct Setpgid {}

#[derive(Debug, Clone)]
pub struct Setpriority {}

#[derive(Debug, Clone)]
pub struct Setregid {}

#[derive(Debug, Clone)]
pub struct Setregid16 {}

#[derive(Debug, Clone)]
pub struct Setresgid {}

#[derive(Debug, Clone)]
pub struct Setresgid16 {}

#[derive(Debug, Clone)]
pub struct Setresuid {}

#[derive(Debug, Clone)]
pub struct Setresuid16 {}

#[derive(Debug, Clone)]
pub struct Setreuid {}

#[derive(Debug, Clone)]
pub struct Setreuid16 {}

#[derive(Debug, Clone)]
pub struct Setrlimit {}

#[derive(Debug, Clone)]
pub struct Setsid {}

#[derive(Debug, Clone)]
pub struct Setsockopt {}

#[derive(Debug, Clone)]
pub struct Settimeofday {}

#[derive(Debug, Clone)]
pub struct Setuid {}

#[derive(Debug, Clone)]
pub struct Setuid16 {}

#[derive(Debug, Clone)]
pub struct Setxattr {}

#[derive(Debug, Clone)]
pub struct Sgetmask {}

#[derive(Debug, Clone)]
pub struct Shmat {}

#[derive(Debug, Clone)]
pub struct Shmctl {}

#[derive(Debug, Clone)]
pub struct Shmdt {}

#[derive(Debug, Clone)]
pub struct Shmget {}

#[derive(Debug, Clone)]
pub struct Shutdown {}

#[derive(Debug, Clone)]
pub struct Sigaction {}

#[derive(Debug, Clone)]
pub struct Sigaltstack {}

#[derive(Debug, Clone)]
pub struct Signal {}

#[derive(Debug, Clone)]
pub struct Signalfd {}

#[derive(Debug, Clone)]
pub struct Signalfd4 {}

#[derive(Debug, Clone)]
pub struct Sigpending {}

#[derive(Debug, Clone)]
pub struct Sigprocmask {}

#[derive(Debug, Clone)]
pub struct Sigreturn {}

#[derive(Debug, Clone)]
pub struct Sigsuspend {}

#[derive(Debug, Clone)]
pub struct Socket {}

#[derive(Debug, Clone)]
pub struct Socketcall {}

#[derive(Debug, Clone)]
pub struct Socketpair {}

#[derive(Debug, Clone)]
pub struct Sparc64Personality {}

#[derive(Debug, Clone)]
pub struct SparcAdjtimex {}

#[derive(Debug, Clone)]
pub struct SparcClockAdjtime {}

#[derive(Debug, Clone)]
pub struct SparcIpc {}

#[derive(Debug, Clone)]
pub struct SparcPipe {}

#[derive(Debug, Clone)]
pub struct SparcRemapFilePages {}

#[derive(Debug, Clone)]
pub struct SparcSigaction {}

#[derive(Debug, Clone)]
pub struct Splice {}

#[derive(Debug, Clone)]
pub struct SpuCreate {}

#[derive(Debug, Clone)]
pub struct SpuRun {}

#[derive(Debug, Clone)]
pub struct Ssetmask {}

#[derive(Debug, Clone)]
pub struct Stat {}

#[derive(Debug, Clone)]
pub struct Stat64 {}

#[derive(Debug, Clone)]
pub struct Statfs {}

#[derive(Debug, Clone)]
pub struct Statfs64 {}

#[derive(Debug, Clone)]
pub struct Statx {}

#[derive(Debug, Clone)]
pub struct Stime {}

#[derive(Debug, Clone)]
pub struct Stime32 {}

#[derive(Debug, Clone)]
pub struct SubpageProt {}

#[derive(Debug, Clone)]
pub struct Swapcontext {}

#[derive(Debug, Clone)]
pub struct Swapoff {}

#[derive(Debug, Clone)]
pub struct Swapon {}

#[derive(Debug, Clone)]
pub struct SwitchEndian {}

#[derive(Debug, Clone)]
pub struct Symlink {}

#[derive(Debug, Clone)]
pub struct Symlinkat {}

#[derive(Debug, Clone)]
pub struct Sync {}

#[derive(Debug, Clone)]
pub struct SyncFileRange {}

#[derive(Debug, Clone)]
pub struct SyncFileRange2 {}

#[derive(Debug, Clone)]
pub struct Syncfs {}

#[derive(Debug, Clone)]
pub struct Sysctl {}

#[derive(Debug, Clone)]
pub struct Sysfs {}

#[derive(Debug, Clone)]
pub struct Sysinfo {}

#[derive(Debug, Clone)]
pub struct Syslog {}

#[derive(Debug, Clone)]
pub struct Sysmips {}

#[derive(Debug, Clone)]
pub struct Tee {}

#[derive(Debug, Clone)]
pub struct Tgkill {}

#[derive(Debug, Clone)]
pub struct Time {}

#[derive(Debug, Clone)]
pub struct Time32 {}

#[derive(Debug, Clone)]
pub struct TimerCreate {}

#[derive(Debug, Clone)]
pub struct TimerDelete {}

#[derive(Debug, Clone)]
pub struct TimerGetoverrun {}

#[derive(Debug, Clone)]
pub struct TimerGettime {}

#[derive(Debug, Clone)]
pub struct TimerGettime32 {}

#[derive(Debug, Clone)]
pub struct TimerSettime {}

#[derive(Debug, Clone)]
pub struct TimerSettime32 {}

#[derive(Debug, Clone)]
pub struct TimerfdCreate {}

#[derive(Debug, Clone)]
pub struct TimerfdGettime {}

#[derive(Debug, Clone)]
pub struct TimerfdGettime32 {}

#[derive(Debug, Clone)]
pub struct TimerfdSettime {}

#[derive(Debug, Clone)]
pub struct TimerfdSettime32 {}

#[derive(Debug, Clone)]
pub struct Times {}

#[derive(Debug, Clone)]
pub struct Tkill {}

#[derive(Debug, Clone)]
pub struct Truncate {}

#[derive(Debug, Clone)]
pub struct Truncate64 {}

#[derive(Debug, Clone)]
pub struct Umask {}

#[derive(Debug, Clone)]
pub struct Umount {}

#[derive(Debug, Clone)]
pub struct Uname {}

#[derive(Debug, Clone)]
pub struct Unlink {}

#[derive(Debug, Clone)]
pub struct Unlinkat {}

#[derive(Debug, Clone)]
pub struct Unshare {}

#[derive(Debug, Clone)]
pub struct Uselib {}

#[derive(Debug, Clone)]
pub struct Userfaultfd {}

#[derive(Debug, Clone)]
pub struct Ustat {}

#[derive(Debug, Clone)]
pub struct Utime {}

#[derive(Debug, Clone)]
pub struct Utime32 {}

#[derive(Debug, Clone)]
pub struct Utimensat {}

#[derive(Debug, Clone)]
pub struct UtimensatTime32 {}

#[derive(Debug, Clone)]
pub struct Utimes {}

#[derive(Debug, Clone)]
pub struct UtimesTime32 {}

#[derive(Debug, Clone)]
pub struct UtrapInstall {}

#[derive(Debug, Clone)]
pub struct Vfork {}

#[derive(Debug, Clone)]
pub struct Vhangup {}

#[derive(Debug, Clone)]
pub struct Vm86 {}

#[derive(Debug, Clone)]
pub struct Vm86old {}

#[derive(Debug, Clone)]
pub struct Vmsplice {}

#[derive(Debug, Clone)]
pub struct Wait4 {}

#[derive(Debug, Clone)]
pub struct Waitid {}

#[derive(Debug, Clone)]
pub struct Waitpid {}

#[derive(Debug, Clone)]
pub struct Write {}

#[derive(Debug, Clone)]
pub struct Writev {}

impl Accept {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Accept {})
    }
}

impl Accept4 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Accept4 {})
    }
}

impl Access {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Access {})
    }
}

impl Acct {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Acct {})
    }
}

impl AddKey {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(AddKey {})
    }
}

impl Adjtimex {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Adjtimex {})
    }
}

impl AdjtimexTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(AdjtimexTime32 {})
    }
}

impl Alarm {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Alarm {})
    }
}

impl AlphaPipe {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(AlphaPipe {})
    }
}

impl ArcGettls {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ArcGettls {})
    }
}

impl ArcSettls {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ArcSettls {})
    }
}

impl ArcUsrCmpxchg {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ArcUsrCmpxchg {})
    }
}

impl Arch32Ftruncate64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arch32Ftruncate64 {})
    }
}

impl Arch32Llseek {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arch32Llseek {})
    }
}

impl Arch32Personality {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arch32Personality {})
    }
}

impl Arch32Pread {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arch32Pread {})
    }
}

impl Arch32Pwrite {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arch32Pwrite {})
    }
}

impl Arch32Sigaction {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arch32Sigaction {})
    }
}

impl Arch32Truncate64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arch32Truncate64 {})
    }
}

impl Arch64Mremap {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arch64Mremap {})
    }
}

impl Arch64Munmap {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arch64Munmap {})
    }
}

impl ArchPrctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ArchPrctl {})
    }
}

impl Arm64Personality {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Arm64Personality {})
    }
}

impl Bdflush {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Bdflush {})
    }
}

impl Bind {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Bind {})
    }
}

impl Bpf {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Bpf {})
    }
}

impl Brk {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Brk {})
    }
}

impl Cachectl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Cachectl {})
    }
}

impl Cacheflush {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Cacheflush {})
    }
}

impl Capget {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Capget {})
    }
}

impl Capset {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Capset {})
    }
}

impl Chdir {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Chdir {})
    }
}

impl Chmod {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Chmod {})
    }
}

impl Chown {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Chown {})
    }
}

impl Chown16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Chown16 {})
    }
}

impl Chroot {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Chroot {})
    }
}

impl ClockAdjtime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockAdjtime {})
    }
}

impl ClockAdjtime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockAdjtime32 {})
    }
}

impl ClockGetres {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockGetres {})
    }
}

impl ClockGetresTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockGetresTime32 {})
    }
}

impl ClockGettime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockGettime {})
    }
}

impl ClockGettime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockGettime32 {})
    }
}

impl ClockNanosleep {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockNanosleep {})
    }
}

impl ClockNanosleepTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockNanosleepTime32 {})
    }
}

impl ClockSettime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockSettime {})
    }
}

impl ClockSettime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ClockSettime32 {})
    }
}

impl Clone {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Clone {})
    }
}

impl Clone3 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Clone3 {})
    }
}

impl Close {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Close {})
    }
}

impl Connect {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Connect {})
    }
}

impl CopyFileRange {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(CopyFileRange {})
    }
}

impl Creat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Creat {})
    }
}

impl CskyFadvise6464 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(CskyFadvise6464 {})
    }
}

impl DebugSetcontext {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(DebugSetcontext {})
    }
}

impl DeleteModule {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(DeleteModule {})
    }
}

impl Dup {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Dup {})
    }
}

impl Dup2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Dup2 {})
    }
}

impl Dup3 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Dup3 {})
    }
}

impl EpollCreate {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(EpollCreate {})
    }
}

impl EpollCreate1 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(EpollCreate1 {})
    }
}

impl EpollCtl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(EpollCtl {})
    }
}

impl EpollPwait {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(EpollPwait {})
    }
}

impl EpollWait {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(EpollWait {})
    }
}

impl Eventfd {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Eventfd {})
    }
}

impl Eventfd2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Eventfd2 {})
    }
}

impl Execve {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        unsafe {
            Ok(Execve {
                filename: OsString::from_process(process, args[0] as *mut c_void)?,
                argv: Vec::<OsString>::from_process(process, args[1] as *mut c_void)?,
                envp: Vec::<OsString>::from_process(process, args[2] as *mut c_void)?,
            })
        }
    }
}

impl Execveat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Execveat {})
    }
}

impl Exit {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Exit {})
    }
}

impl ExitGroup {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ExitGroup {})
    }
}

impl Faccessat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Faccessat {})
    }
}

impl Fadvise64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fadvise64 {})
    }
}

impl Fadvise6464 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fadvise6464 {})
    }
}

impl Fadvise6464Wrapper {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fadvise6464Wrapper {})
    }
}

impl Fallocate {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fallocate {})
    }
}

impl FanotifyInit {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(FanotifyInit {})
    }
}

impl FanotifyMark {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(FanotifyMark {})
    }
}

impl Fchdir {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fchdir {})
    }
}

impl Fchmod {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fchmod {})
    }
}

impl Fchmodat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fchmodat {})
    }
}

impl Fchown {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fchown {})
    }
}

impl Fchown16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fchown16 {})
    }
}

impl Fchownat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fchownat {})
    }
}

impl Fcntl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fcntl {})
    }
}

impl Fcntl64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fcntl64 {})
    }
}

impl Fdatasync {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fdatasync {})
    }
}

impl Fgetxattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fgetxattr {})
    }
}

impl FinitModule {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(FinitModule {})
    }
}

impl Flistxattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Flistxattr {})
    }
}

impl Flock {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Flock {})
    }
}

impl Fork {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fork {})
    }
}

impl FpUdfiexCrtl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(FpUdfiexCrtl {})
    }
}

impl Fremovexattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fremovexattr {})
    }
}

impl Fsconfig {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fsconfig {})
    }
}

impl Fsetxattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fsetxattr {})
    }
}

impl Fsmount {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fsmount {})
    }
}

impl Fsopen {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fsopen {})
    }
}

impl Fspick {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fspick {})
    }
}

impl Fstat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fstat {})
    }
}

impl Fstat64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fstat64 {})
    }
}

impl Fstatat64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fstatat64 {})
    }
}

impl Fstatfs {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fstatfs {})
    }
}

impl Fstatfs64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fstatfs64 {})
    }
}

impl Fsync {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Fsync {})
    }
}

impl Ftruncate {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Ftruncate {})
    }
}

impl Ftruncate64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Ftruncate64 {})
    }
}

impl Futex {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Futex {})
    }
}

impl FutexTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(FutexTime32 {})
    }
}

impl Futimesat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Futimesat {})
    }
}

impl FutimesatTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(FutimesatTime32 {})
    }
}

impl GetMempolicy {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(GetMempolicy {})
    }
}

impl GetRobustList {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(GetRobustList {})
    }
}

impl GetThreadArea {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(GetThreadArea {})
    }
}

impl Getcpu {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getcpu {})
    }
}

impl Getcwd {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getcwd {})
    }
}

impl Getdents {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getdents {})
    }
}

impl Getdents64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getdents64 {})
    }
}

impl Getdomainname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getdomainname {})
    }
}

impl Getdtablesize {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getdtablesize {})
    }
}

impl Getegid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getegid {})
    }
}

impl Getegid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getegid16 {})
    }
}

impl Geteuid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Geteuid {})
    }
}

impl Geteuid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Geteuid16 {})
    }
}

impl Getgid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getgid {})
    }
}

impl Getgid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getgid16 {})
    }
}

impl Getgroups {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getgroups {})
    }
}

impl Getgroups16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getgroups16 {})
    }
}

impl Gethostname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Gethostname {})
    }
}

impl Getitimer {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getitimer {})
    }
}

impl Getpagesize {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getpagesize {})
    }
}

impl Getpeername {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getpeername {})
    }
}

impl Getpgid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getpgid {})
    }
}

impl Getpgrp {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getpgrp {})
    }
}

impl Getpid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getpid {})
    }
}

impl Getppid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getppid {})
    }
}

impl Getpriority {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getpriority {})
    }
}

impl Getrandom {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getrandom {})
    }
}

impl Getresgid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getresgid {})
    }
}

impl Getresgid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getresgid16 {})
    }
}

impl Getresuid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getresuid {})
    }
}

impl Getresuid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getresuid16 {})
    }
}

impl Getrlimit {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getrlimit {})
    }
}

impl Getrusage {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getrusage {})
    }
}

impl Getsid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getsid {})
    }
}

impl Getsockname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getsockname {})
    }
}

impl Getsockopt {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getsockopt {})
    }
}

impl Gettid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Gettid {})
    }
}

impl Gettimeofday {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Gettimeofday {})
    }
}

impl Getuid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getuid {})
    }
}

impl Getuid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getuid16 {})
    }
}

impl Getxattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getxattr {})
    }
}

impl Getxgid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getxgid {})
    }
}

impl Getxpid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getxpid {})
    }
}

impl Getxuid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Getxuid {})
    }
}

impl InitModule {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(InitModule {})
    }
}

impl InotifyAddWatch {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(InotifyAddWatch {})
    }
}

impl InotifyInit {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(InotifyInit {})
    }
}

impl InotifyInit1 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(InotifyInit1 {})
    }
}

impl InotifyRmWatch {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(InotifyRmWatch {})
    }
}

impl IoCancel {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoCancel {})
    }
}

impl IoDestroy {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoDestroy {})
    }
}

impl IoGetevents {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoGetevents {})
    }
}

impl IoGeteventsTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoGeteventsTime32 {})
    }
}

impl IoPgetevents {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoPgetevents {})
    }
}

impl IoPgeteventsTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoPgeteventsTime32 {})
    }
}

impl IoSetup {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoSetup {})
    }
}

impl IoSubmit {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoSubmit {})
    }
}

impl IoUringEnter {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoUringEnter {})
    }
}

impl IoUringRegister {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoUringRegister {})
    }
}

impl IoUringSetup {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoUringSetup {})
    }
}

impl Ioctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Ioctl {})
    }
}

impl Ioperm {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Ioperm {})
    }
}

impl Iopl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Iopl {})
    }
}

impl IoprioGet {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoprioGet {})
    }
}

impl IoprioSet {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(IoprioSet {})
    }
}

impl Ipc {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Ipc {})
    }
}

impl Kcmp {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Kcmp {})
    }
}

impl KernFeatures {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(KernFeatures {})
    }
}

impl KexecFileLoad {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(KexecFileLoad {})
    }
}

impl KexecLoad {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(KexecLoad {})
    }
}

impl Keyctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Keyctl {})
    }
}

impl Kill {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Kill {})
    }
}

impl Lchown {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Lchown {})
    }
}

impl Lchown16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Lchown16 {})
    }
}

impl Lgetxattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Lgetxattr {})
    }
}

impl Link {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Link {})
    }
}

impl Linkat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Linkat {})
    }
}

impl Listen {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Listen {})
    }
}

impl Listxattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Listxattr {})
    }
}

impl Llistxattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Llistxattr {})
    }
}

impl Llseek {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Llseek {})
    }
}

impl LookupDcookie {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(LookupDcookie {})
    }
}

impl Lremovexattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Lremovexattr {})
    }
}

impl Lseek {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Lseek {})
    }
}

impl Lsetxattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Lsetxattr {})
    }
}

impl Lstat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Lstat {})
    }
}

impl Lstat64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Lstat64 {})
    }
}

impl Madvise {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Madvise {})
    }
}

impl Mbind {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mbind {})
    }
}

impl Membarrier {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Membarrier {})
    }
}

impl MemfdCreate {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MemfdCreate {})
    }
}

impl MemoryOrdering {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MemoryOrdering {})
    }
}

impl MigratePages {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MigratePages {})
    }
}

impl Mincore {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mincore {})
    }
}

impl MipsMmap {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MipsMmap {})
    }
}

impl MipsMmap2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MipsMmap2 {})
    }
}

impl Mkdir {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mkdir {})
    }
}

impl Mkdirat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mkdirat {})
    }
}

impl Mknod {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mknod {})
    }
}

impl Mknodat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mknodat {})
    }
}

impl Mlock {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mlock {})
    }
}

impl Mlock2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mlock2 {})
    }
}

impl Mlockall {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mlockall {})
    }
}

impl Mmap {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mmap {})
    }
}

impl Mmap2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mmap2 {})
    }
}

impl MmapPgoff {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MmapPgoff {})
    }
}

impl ModifyLdt {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ModifyLdt {})
    }
}

impl Mount {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mount {})
    }
}

impl MoveMount {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MoveMount {})
    }
}

impl MovePages {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MovePages {})
    }
}

impl Mprotect {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mprotect {})
    }
}

impl MqGetsetattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MqGetsetattr {})
    }
}

impl MqNotify {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MqNotify {})
    }
}

impl MqOpen {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MqOpen {})
    }
}

impl MqTimedreceive {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MqTimedreceive {})
    }
}

impl MqTimedreceiveTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MqTimedreceiveTime32 {})
    }
}

impl MqTimedsend {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MqTimedsend {})
    }
}

impl MqTimedsendTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MqTimedsendTime32 {})
    }
}

impl MqUnlink {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(MqUnlink {})
    }
}

impl Mremap {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Mremap {})
    }
}

impl Msgctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Msgctl {})
    }
}

impl Msgget {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Msgget {})
    }
}

impl Msgrcv {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Msgrcv {})
    }
}

impl Msgsnd {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Msgsnd {})
    }
}

impl Msync {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Msync {})
    }
}

impl Munlock {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Munlock {})
    }
}

impl Munlockall {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Munlockall {})
    }
}

impl Munmap {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Munmap {})
    }
}

impl NameToHandleAt {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(NameToHandleAt {})
    }
}

impl Nanosleep {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Nanosleep {})
    }
}

impl NanosleepTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(NanosleepTime32 {})
    }
}

impl Newfstat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Newfstat {})
    }
}

impl Newfstatat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Newfstatat {})
    }
}

impl Newlstat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Newlstat {})
    }
}

impl Newstat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Newstat {})
    }
}

impl Newuname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Newuname {})
    }
}

impl NiSyscall {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(NiSyscall {})
    }
}

impl Nice {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Nice {})
    }
}

impl NisSyscall {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(NisSyscall {})
    }
}

impl OldAdjtimex {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OldAdjtimex {})
    }
}

impl OldGetrlimit {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OldGetrlimit {})
    }
}

impl OldMmap {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OldMmap {})
    }
}

impl OldMsgctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OldMsgctl {})
    }
}

impl OldReaddir {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OldReaddir {})
    }
}

impl OldSelect {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OldSelect {})
    }
}

impl OldSemctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OldSemctl {})
    }
}

impl OldShmctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OldShmctl {})
    }
}

impl Oldumount {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Oldumount {})
    }
}

impl Olduname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Olduname {})
    }
}

impl Open {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Open {})
    }
}

impl OpenByHandleAt {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OpenByHandleAt {})
    }
}

impl OpenTree {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OpenTree {})
    }
}

impl Openat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Openat {})
    }
}

impl Openat2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Openat2 {})
    }
}

impl OsfBrk {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfBrk {})
    }
}

impl OsfFstat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfFstat {})
    }
}

impl OsfFstatfs {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfFstatfs {})
    }
}

impl OsfFstatfs64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfFstatfs64 {})
    }
}

impl OsfGetdirentries {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfGetdirentries {})
    }
}

impl OsfGetdomainname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfGetdomainname {})
    }
}

impl OsfGetpriority {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfGetpriority {})
    }
}

impl OsfGetrusage {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfGetrusage {})
    }
}

impl OsfGetsysinfo {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfGetsysinfo {})
    }
}

impl OsfGettimeofday {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfGettimeofday {})
    }
}

impl OsfLstat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfLstat {})
    }
}

impl OsfMmap {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfMmap {})
    }
}

impl OsfMount {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfMount {})
    }
}

impl OsfProplistSyscall {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfProplistSyscall {})
    }
}

impl OsfReadv {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfReadv {})
    }
}

impl OsfSelect {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfSelect {})
    }
}

impl OsfSetProgramAttributes {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfSetProgramAttributes {})
    }
}

impl OsfSetsysinfo {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfSetsysinfo {})
    }
}

impl OsfSettimeofday {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfSettimeofday {})
    }
}

impl OsfSigaction {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfSigaction {})
    }
}

impl OsfSigprocmask {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfSigprocmask {})
    }
}

impl OsfSigstack {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfSigstack {})
    }
}

impl OsfStat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfStat {})
    }
}

impl OsfStatfs {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfStatfs {})
    }
}

impl OsfStatfs64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfStatfs64 {})
    }
}

impl OsfSysinfo {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfSysinfo {})
    }
}

impl OsfUsleepThread {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfUsleepThread {})
    }
}

impl OsfUtimes {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfUtimes {})
    }
}

impl OsfUtsname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfUtsname {})
    }
}

impl OsfWait4 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfWait4 {})
    }
}

impl OsfWritev {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(OsfWritev {})
    }
}

impl Pause {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Pause {})
    }
}

impl PciconfigIobase {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PciconfigIobase {})
    }
}

impl PciconfigRead {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PciconfigRead {})
    }
}

impl PciconfigWrite {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PciconfigWrite {})
    }
}

impl PerfEventOpen {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PerfEventOpen {})
    }
}

impl Personality {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Personality {})
    }
}

impl PidfdGetfd {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PidfdGetfd {})
    }
}

impl PidfdOpen {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PidfdOpen {})
    }
}

impl PidfdSendSignal {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PidfdSendSignal {})
    }
}

impl Pipe {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Pipe {})
    }
}

impl Pipe2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Pipe2 {})
    }
}

impl PivotRoot {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PivotRoot {})
    }
}

impl PkeyAlloc {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PkeyAlloc {})
    }
}

impl PkeyFree {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PkeyFree {})
    }
}

impl PkeyMprotect {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PkeyMprotect {})
    }
}

impl Poll {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Poll {})
    }
}

impl Ppoll {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Ppoll {})
    }
}

impl PpollTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(PpollTime32 {})
    }
}

impl Prctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Prctl {})
    }
}

impl Pread64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Pread64 {})
    }
}

impl Preadv {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Preadv {})
    }
}

impl Preadv2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Preadv2 {})
    }
}

impl Prlimit64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Prlimit64 {})
    }
}

impl ProcessVmReadv {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ProcessVmReadv {})
    }
}

impl ProcessVmWritev {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(ProcessVmWritev {})
    }
}

impl Pselect6 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Pselect6 {})
    }
}

impl Pselect6Time32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Pselect6Time32 {})
    }
}

impl Ptrace {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Ptrace {})
    }
}

impl Pwrite64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Pwrite64 {})
    }
}

impl Pwritev {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Pwritev {})
    }
}

impl Pwritev2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Pwritev2 {})
    }
}

impl Quotactl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Quotactl {})
    }
}

impl Read {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Read {})
    }
}

impl Readahead {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Readahead {})
    }
}

impl Readlink {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Readlink {})
    }
}

impl Readlinkat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Readlinkat {})
    }
}

impl Readv {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Readv {})
    }
}

impl Reboot {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Reboot {})
    }
}

impl Recv {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Recv {})
    }
}

impl Recvfrom {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Recvfrom {})
    }
}

impl Recvmmsg {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Recvmmsg {})
    }
}

impl RecvmmsgTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RecvmmsgTime32 {})
    }
}

impl Recvmsg {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Recvmsg {})
    }
}

impl RemapFilePages {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RemapFilePages {})
    }
}

impl Removexattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Removexattr {})
    }
}

impl Rename {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Rename {})
    }
}

impl Renameat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Renameat {})
    }
}

impl Renameat2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Renameat2 {})
    }
}

impl RequestKey {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RequestKey {})
    }
}

impl RestartSyscall {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RestartSyscall {})
    }
}

impl RiscvFlushIcache {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RiscvFlushIcache {})
    }
}

impl Rmdir {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Rmdir {})
    }
}

impl Rseq {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Rseq {})
    }
}

impl RtSigaction {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RtSigaction {})
    }
}

impl RtSigpending {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RtSigpending {})
    }
}

impl RtSigprocmask {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RtSigprocmask {})
    }
}

impl RtSigqueueinfo {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RtSigqueueinfo {})
    }
}

impl RtSigreturn {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RtSigreturn {})
    }
}

impl RtSigsuspend {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RtSigsuspend {})
    }
}

impl RtSigtimedwait {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RtSigtimedwait {})
    }
}

impl RtSigtimedwaitTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RtSigtimedwaitTime32 {})
    }
}

impl RtTgsigqueueinfo {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(RtTgsigqueueinfo {})
    }
}

impl Rtas {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Rtas {})
    }
}

impl S390GuardedStorage {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(S390GuardedStorage {})
    }
}

impl S390Ipc {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(S390Ipc {})
    }
}

impl S390PciMmioRead {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(S390PciMmioRead {})
    }
}

impl S390PciMmioWrite {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(S390PciMmioWrite {})
    }
}

impl S390Personality {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(S390Personality {})
    }
}

impl S390RuntimeInstr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(S390RuntimeInstr {})
    }
}

impl S390Sthyi {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(S390Sthyi {})
    }
}

impl SchedGetPriorityMax {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedGetPriorityMax {})
    }
}

impl SchedGetPriorityMin {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedGetPriorityMin {})
    }
}

impl SchedGetaffinity {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedGetaffinity {})
    }
}

impl SchedGetattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedGetattr {})
    }
}

impl SchedGetparam {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedGetparam {})
    }
}

impl SchedGetscheduler {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedGetscheduler {})
    }
}

impl SchedRrGetInterval {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedRrGetInterval {})
    }
}

impl SchedRrGetIntervalTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedRrGetIntervalTime32 {})
    }
}

impl SchedSetaffinity {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedSetaffinity {})
    }
}

impl SchedSetattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedSetattr {})
    }
}

impl SchedSetparam {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedSetparam {})
    }
}

impl SchedSetscheduler {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedSetscheduler {})
    }
}

impl SchedYield {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SchedYield {})
    }
}

impl Seccomp {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Seccomp {})
    }
}

impl Select {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Select {})
    }
}

impl Semctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Semctl {})
    }
}

impl Semget {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Semget {})
    }
}

impl Semop {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Semop {})
    }
}

impl Semtimedop {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Semtimedop {})
    }
}

impl SemtimedopTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SemtimedopTime32 {})
    }
}

impl Send {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Send {})
    }
}

impl Sendfile {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sendfile {})
    }
}

impl Sendfile64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sendfile64 {})
    }
}

impl Sendmmsg {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sendmmsg {})
    }
}

impl Sendmsg {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sendmsg {})
    }
}

impl Sendto {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sendto {})
    }
}

impl SetMempolicy {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SetMempolicy {})
    }
}

impl SetRobustList {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SetRobustList {})
    }
}

impl SetThreadArea {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SetThreadArea {})
    }
}

impl SetTidAddress {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SetTidAddress {})
    }
}

impl Setdomainname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setdomainname {})
    }
}

impl Setfsgid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setfsgid {})
    }
}

impl Setfsgid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setfsgid16 {})
    }
}

impl Setfsuid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setfsuid {})
    }
}

impl Setfsuid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setfsuid16 {})
    }
}

impl Setgid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setgid {})
    }
}

impl Setgid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setgid16 {})
    }
}

impl Setgroups {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setgroups {})
    }
}

impl Setgroups16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setgroups16 {})
    }
}

impl Sethae {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sethae {})
    }
}

impl Sethostname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sethostname {})
    }
}

impl Setitimer {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setitimer {})
    }
}

impl Setns {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setns {})
    }
}

impl Setpgid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setpgid {})
    }
}

impl Setpriority {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setpriority {})
    }
}

impl Setregid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setregid {})
    }
}

impl Setregid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setregid16 {})
    }
}

impl Setresgid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setresgid {})
    }
}

impl Setresgid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setresgid16 {})
    }
}

impl Setresuid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setresuid {})
    }
}

impl Setresuid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setresuid16 {})
    }
}

impl Setreuid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setreuid {})
    }
}

impl Setreuid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setreuid16 {})
    }
}

impl Setrlimit {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setrlimit {})
    }
}

impl Setsid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setsid {})
    }
}

impl Setsockopt {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setsockopt {})
    }
}

impl Settimeofday {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Settimeofday {})
    }
}

impl Setuid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setuid {})
    }
}

impl Setuid16 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setuid16 {})
    }
}

impl Setxattr {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Setxattr {})
    }
}

impl Sgetmask {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sgetmask {})
    }
}

impl Shmat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Shmat {})
    }
}

impl Shmctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Shmctl {})
    }
}

impl Shmdt {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Shmdt {})
    }
}

impl Shmget {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Shmget {})
    }
}

impl Shutdown {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Shutdown {})
    }
}

impl Sigaction {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sigaction {})
    }
}

impl Sigaltstack {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sigaltstack {})
    }
}

impl Signal {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Signal {})
    }
}

impl Signalfd {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Signalfd {})
    }
}

impl Signalfd4 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Signalfd4 {})
    }
}

impl Sigpending {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sigpending {})
    }
}

impl Sigprocmask {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sigprocmask {})
    }
}

impl Sigreturn {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sigreturn {})
    }
}

impl Sigsuspend {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sigsuspend {})
    }
}

impl Socket {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Socket {})
    }
}

impl Socketcall {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Socketcall {})
    }
}

impl Socketpair {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Socketpair {})
    }
}

impl Sparc64Personality {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sparc64Personality {})
    }
}

impl SparcAdjtimex {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SparcAdjtimex {})
    }
}

impl SparcClockAdjtime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SparcClockAdjtime {})
    }
}

impl SparcIpc {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SparcIpc {})
    }
}

impl SparcPipe {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SparcPipe {})
    }
}

impl SparcRemapFilePages {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SparcRemapFilePages {})
    }
}

impl SparcSigaction {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SparcSigaction {})
    }
}

impl Splice {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Splice {})
    }
}

impl SpuCreate {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SpuCreate {})
    }
}

impl SpuRun {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SpuRun {})
    }
}

impl Ssetmask {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Ssetmask {})
    }
}

impl Stat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Stat {})
    }
}

impl Stat64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Stat64 {})
    }
}

impl Statfs {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Statfs {})
    }
}

impl Statfs64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Statfs64 {})
    }
}

impl Statx {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Statx {})
    }
}

impl Stime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Stime {})
    }
}

impl Stime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Stime32 {})
    }
}

impl SubpageProt {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SubpageProt {})
    }
}

impl Swapcontext {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Swapcontext {})
    }
}

impl Swapoff {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Swapoff {})
    }
}

impl Swapon {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Swapon {})
    }
}

impl SwitchEndian {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SwitchEndian {})
    }
}

impl Symlink {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Symlink {})
    }
}

impl Symlinkat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Symlinkat {})
    }
}

impl Sync {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sync {})
    }
}

impl SyncFileRange {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SyncFileRange {})
    }
}

impl SyncFileRange2 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(SyncFileRange2 {})
    }
}

impl Syncfs {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Syncfs {})
    }
}

impl Sysctl {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sysctl {})
    }
}

impl Sysfs {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sysfs {})
    }
}

impl Sysinfo {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sysinfo {})
    }
}

impl Syslog {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Syslog {})
    }
}

impl Sysmips {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Sysmips {})
    }
}

impl Tee {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Tee {})
    }
}

impl Tgkill {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Tgkill {})
    }
}

impl Time {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Time {})
    }
}

impl Time32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Time32 {})
    }
}

impl TimerCreate {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerCreate {})
    }
}

impl TimerDelete {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerDelete {})
    }
}

impl TimerGetoverrun {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerGetoverrun {})
    }
}

impl TimerGettime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerGettime {})
    }
}

impl TimerGettime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerGettime32 {})
    }
}

impl TimerSettime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerSettime {})
    }
}

impl TimerSettime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerSettime32 {})
    }
}

impl TimerfdCreate {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerfdCreate {})
    }
}

impl TimerfdGettime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerfdGettime {})
    }
}

impl TimerfdGettime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerfdGettime32 {})
    }
}

impl TimerfdSettime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerfdSettime {})
    }
}

impl TimerfdSettime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(TimerfdSettime32 {})
    }
}

impl Times {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Times {})
    }
}

impl Tkill {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Tkill {})
    }
}

impl Truncate {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Truncate {})
    }
}

impl Truncate64 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Truncate64 {})
    }
}

impl Umask {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Umask {})
    }
}

impl Umount {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Umount {})
    }
}

impl Uname {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Uname {})
    }
}

impl Unlink {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Unlink {})
    }
}

impl Unlinkat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Unlinkat {})
    }
}

impl Unshare {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Unshare {})
    }
}

impl Uselib {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Uselib {})
    }
}

impl Userfaultfd {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Userfaultfd {})
    }
}

impl Ustat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Ustat {})
    }
}

impl Utime {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Utime {})
    }
}

impl Utime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Utime32 {})
    }
}

impl Utimensat {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Utimensat {})
    }
}

impl UtimensatTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(UtimensatTime32 {})
    }
}

impl Utimes {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Utimes {})
    }
}

impl UtimesTime32 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(UtimesTime32 {})
    }
}

impl UtrapInstall {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(UtrapInstall {})
    }
}

impl Vfork {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Vfork {})
    }
}

impl Vhangup {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Vhangup {})
    }
}

impl Vm86 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Vm86 {})
    }
}

impl Vm86old {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Vm86old {})
    }
}

impl Vmsplice {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Vmsplice {})
    }
}

impl Wait4 {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Wait4 {})
    }
}

impl Waitid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Waitid {})
    }
}

impl Waitpid {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Waitpid {})
    }
}

impl Write {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Write {})
    }
}

impl Writev {
    pub fn from_args(args: [u64; 6], process: &StoppedProcess) -> Result<Self, OsError> {
        Ok(Writev {})
    }
}
