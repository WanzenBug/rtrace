use std::io::ErrorKind;

use crate::{OsError, StoppedProcess};

mod syscall_defs_enter;
mod syscall_defs_exit;

pub use syscall_defs_enter::*;
pub use syscall_defs_exit::*;

#[derive(Debug, Clone)]
pub enum SyscallEnter {
    Accept(Accept),
    Accept4(Accept4),
    Access(Access),
    Acct(Acct),
    AddKey(AddKey),
    Adjtimex(Adjtimex),
    AdjtimexTime32(AdjtimexTime32),
    Alarm(Alarm),
    AlphaPipe(AlphaPipe),
    ArcGettls(ArcGettls),
    ArcSettls(ArcSettls),
    ArcUsrCmpxchg(ArcUsrCmpxchg),
    Arch32Ftruncate64(Arch32Ftruncate64),
    Arch32Llseek(Arch32Llseek),
    Arch32Personality(Arch32Personality),
    Arch32Pread(Arch32Pread),
    Arch32Pwrite(Arch32Pwrite),
    Arch32Sigaction(Arch32Sigaction),
    Arch32Truncate64(Arch32Truncate64),
    Arch64Mremap(Arch64Mremap),
    Arch64Munmap(Arch64Munmap),
    ArchPrctl(ArchPrctl),
    Arm64Personality(Arm64Personality),
    Bdflush(Bdflush),
    Bind(Bind),
    Bpf(Bpf),
    Brk(Brk),
    Cachectl(Cachectl),
    Cacheflush(Cacheflush),
    Capget(Capget),
    Capset(Capset),
    Chdir(Chdir),
    Chmod(Chmod),
    Chown(Chown),
    Chown16(Chown16),
    Chroot(Chroot),
    ClockAdjtime(ClockAdjtime),
    ClockAdjtime32(ClockAdjtime32),
    ClockGetres(ClockGetres),
    ClockGetresTime32(ClockGetresTime32),
    ClockGettime(ClockGettime),
    ClockGettime32(ClockGettime32),
    ClockNanosleep(ClockNanosleep),
    ClockNanosleepTime32(ClockNanosleepTime32),
    ClockSettime(ClockSettime),
    ClockSettime32(ClockSettime32),
    Clone(Clone),
    Clone3(Clone3),
    Close(Close),
    Connect(Connect),
    CopyFileRange(CopyFileRange),
    Creat(Creat),
    CskyFadvise6464(CskyFadvise6464),
    DebugSetcontext(DebugSetcontext),
    DeleteModule(DeleteModule),
    Dup(Dup),
    Dup2(Dup2),
    Dup3(Dup3),
    EpollCreate(EpollCreate),
    EpollCreate1(EpollCreate1),
    EpollCtl(EpollCtl),
    EpollPwait(EpollPwait),
    EpollWait(EpollWait),
    Eventfd(Eventfd),
    Eventfd2(Eventfd2),
    Execve(Execve),
    Execveat(Execveat),
    Exit(Exit),
    ExitGroup(ExitGroup),
    Faccessat(Faccessat),
    Fadvise64(Fadvise64),
    Fadvise6464(Fadvise6464),
    Fadvise6464Wrapper(Fadvise6464Wrapper),
    Fallocate(Fallocate),
    FanotifyInit(FanotifyInit),
    FanotifyMark(FanotifyMark),
    Fchdir(Fchdir),
    Fchmod(Fchmod),
    Fchmodat(Fchmodat),
    Fchown(Fchown),
    Fchown16(Fchown16),
    Fchownat(Fchownat),
    Fcntl(Fcntl),
    Fcntl64(Fcntl64),
    Fdatasync(Fdatasync),
    Fgetxattr(Fgetxattr),
    FinitModule(FinitModule),
    Flistxattr(Flistxattr),
    Flock(Flock),
    Fork(Fork),
    FpUdfiexCrtl(FpUdfiexCrtl),
    Fremovexattr(Fremovexattr),
    Fsconfig(Fsconfig),
    Fsetxattr(Fsetxattr),
    Fsmount(Fsmount),
    Fsopen(Fsopen),
    Fspick(Fspick),
    Fstat(Fstat),
    Fstat64(Fstat64),
    Fstatat64(Fstatat64),
    Fstatfs(Fstatfs),
    Fstatfs64(Fstatfs64),
    Fsync(Fsync),
    Ftruncate(Ftruncate),
    Ftruncate64(Ftruncate64),
    Futex(Futex),
    FutexTime32(FutexTime32),
    Futimesat(Futimesat),
    FutimesatTime32(FutimesatTime32),
    GetMempolicy(GetMempolicy),
    GetRobustList(GetRobustList),
    GetThreadArea(GetThreadArea),
    Getcpu(Getcpu),
    Getcwd(Getcwd),
    Getdents(Getdents),
    Getdents64(Getdents64),
    Getdomainname(Getdomainname),
    Getdtablesize(Getdtablesize),
    Getegid(Getegid),
    Getegid16(Getegid16),
    Geteuid(Geteuid),
    Geteuid16(Geteuid16),
    Getgid(Getgid),
    Getgid16(Getgid16),
    Getgroups(Getgroups),
    Getgroups16(Getgroups16),
    Gethostname(Gethostname),
    Getitimer(Getitimer),
    Getpagesize(Getpagesize),
    Getpeername(Getpeername),
    Getpgid(Getpgid),
    Getpgrp(Getpgrp),
    Getpid(Getpid),
    Getppid(Getppid),
    Getpriority(Getpriority),
    Getrandom(Getrandom),
    Getresgid(Getresgid),
    Getresgid16(Getresgid16),
    Getresuid(Getresuid),
    Getresuid16(Getresuid16),
    Getrlimit(Getrlimit),
    Getrusage(Getrusage),
    Getsid(Getsid),
    Getsockname(Getsockname),
    Getsockopt(Getsockopt),
    Gettid(Gettid),
    Gettimeofday(Gettimeofday),
    Getuid(Getuid),
    Getuid16(Getuid16),
    Getxattr(Getxattr),
    Getxgid(Getxgid),
    Getxpid(Getxpid),
    Getxuid(Getxuid),
    InitModule(InitModule),
    InotifyAddWatch(InotifyAddWatch),
    InotifyInit(InotifyInit),
    InotifyInit1(InotifyInit1),
    InotifyRmWatch(InotifyRmWatch),
    IoCancel(IoCancel),
    IoDestroy(IoDestroy),
    IoGetevents(IoGetevents),
    IoGeteventsTime32(IoGeteventsTime32),
    IoPgetevents(IoPgetevents),
    IoPgeteventsTime32(IoPgeteventsTime32),
    IoSetup(IoSetup),
    IoSubmit(IoSubmit),
    IoUringEnter(IoUringEnter),
    IoUringRegister(IoUringRegister),
    IoUringSetup(IoUringSetup),
    Ioctl(Ioctl),
    Ioperm(Ioperm),
    Iopl(Iopl),
    IoprioGet(IoprioGet),
    IoprioSet(IoprioSet),
    Ipc(Ipc),
    Kcmp(Kcmp),
    KernFeatures(KernFeatures),
    KexecFileLoad(KexecFileLoad),
    KexecLoad(KexecLoad),
    Keyctl(Keyctl),
    Kill(Kill),
    Lchown(Lchown),
    Lchown16(Lchown16),
    Lgetxattr(Lgetxattr),
    Link(Link),
    Linkat(Linkat),
    Listen(Listen),
    Listxattr(Listxattr),
    Llistxattr(Llistxattr),
    Llseek(Llseek),
    LookupDcookie(LookupDcookie),
    Lremovexattr(Lremovexattr),
    Lseek(Lseek),
    Lsetxattr(Lsetxattr),
    Lstat(Lstat),
    Lstat64(Lstat64),
    Madvise(Madvise),
    Mbind(Mbind),
    Membarrier(Membarrier),
    MemfdCreate(MemfdCreate),
    MemoryOrdering(MemoryOrdering),
    MigratePages(MigratePages),
    Mincore(Mincore),
    MipsMmap(MipsMmap),
    MipsMmap2(MipsMmap2),
    Mkdir(Mkdir),
    Mkdirat(Mkdirat),
    Mknod(Mknod),
    Mknodat(Mknodat),
    Mlock(Mlock),
    Mlock2(Mlock2),
    Mlockall(Mlockall),
    Mmap(Mmap),
    Mmap2(Mmap2),
    MmapPgoff(MmapPgoff),
    ModifyLdt(ModifyLdt),
    Mount(Mount),
    MoveMount(MoveMount),
    MovePages(MovePages),
    Mprotect(Mprotect),
    MqGetsetattr(MqGetsetattr),
    MqNotify(MqNotify),
    MqOpen(MqOpen),
    MqTimedreceive(MqTimedreceive),
    MqTimedreceiveTime32(MqTimedreceiveTime32),
    MqTimedsend(MqTimedsend),
    MqTimedsendTime32(MqTimedsendTime32),
    MqUnlink(MqUnlink),
    Mremap(Mremap),
    Msgctl(Msgctl),
    Msgget(Msgget),
    Msgrcv(Msgrcv),
    Msgsnd(Msgsnd),
    Msync(Msync),
    Munlock(Munlock),
    Munlockall(Munlockall),
    Munmap(Munmap),
    NameToHandleAt(NameToHandleAt),
    Nanosleep(Nanosleep),
    NanosleepTime32(NanosleepTime32),
    Newfstat(Newfstat),
    Newfstatat(Newfstatat),
    Newlstat(Newlstat),
    Newstat(Newstat),
    Newuname(Newuname),
    NiSyscall(NiSyscall),
    Nice(Nice),
    NisSyscall(NisSyscall),
    OldAdjtimex(OldAdjtimex),
    OldGetrlimit(OldGetrlimit),
    OldMmap(OldMmap),
    OldMsgctl(OldMsgctl),
    OldReaddir(OldReaddir),
    OldSelect(OldSelect),
    OldSemctl(OldSemctl),
    OldShmctl(OldShmctl),
    Oldumount(Oldumount),
    Olduname(Olduname),
    Open(Open),
    OpenByHandleAt(OpenByHandleAt),
    OpenTree(OpenTree),
    Openat(Openat),
    Openat2(Openat2),
    OsfBrk(OsfBrk),
    OsfFstat(OsfFstat),
    OsfFstatfs(OsfFstatfs),
    OsfFstatfs64(OsfFstatfs64),
    OsfGetdirentries(OsfGetdirentries),
    OsfGetdomainname(OsfGetdomainname),
    OsfGetpriority(OsfGetpriority),
    OsfGetrusage(OsfGetrusage),
    OsfGetsysinfo(OsfGetsysinfo),
    OsfGettimeofday(OsfGettimeofday),
    OsfLstat(OsfLstat),
    OsfMmap(OsfMmap),
    OsfMount(OsfMount),
    OsfProplistSyscall(OsfProplistSyscall),
    OsfReadv(OsfReadv),
    OsfSelect(OsfSelect),
    OsfSetProgramAttributes(OsfSetProgramAttributes),
    OsfSetsysinfo(OsfSetsysinfo),
    OsfSettimeofday(OsfSettimeofday),
    OsfSigaction(OsfSigaction),
    OsfSigprocmask(OsfSigprocmask),
    OsfSigstack(OsfSigstack),
    OsfStat(OsfStat),
    OsfStatfs(OsfStatfs),
    OsfStatfs64(OsfStatfs64),
    OsfSysinfo(OsfSysinfo),
    OsfUsleepThread(OsfUsleepThread),
    OsfUtimes(OsfUtimes),
    OsfUtsname(OsfUtsname),
    OsfWait4(OsfWait4),
    OsfWritev(OsfWritev),
    Pause(Pause),
    PciconfigIobase(PciconfigIobase),
    PciconfigRead(PciconfigRead),
    PciconfigWrite(PciconfigWrite),
    PerfEventOpen(PerfEventOpen),
    Personality(Personality),
    PidfdGetfd(PidfdGetfd),
    PidfdOpen(PidfdOpen),
    PidfdSendSignal(PidfdSendSignal),
    Pipe(Pipe),
    Pipe2(Pipe2),
    PivotRoot(PivotRoot),
    PkeyAlloc(PkeyAlloc),
    PkeyFree(PkeyFree),
    PkeyMprotect(PkeyMprotect),
    Poll(Poll),
    Ppoll(Ppoll),
    PpollTime32(PpollTime32),
    Prctl(Prctl),
    Pread64(Pread64),
    Preadv(Preadv),
    Preadv2(Preadv2),
    Prlimit64(Prlimit64),
    ProcessVmReadv(ProcessVmReadv),
    ProcessVmWritev(ProcessVmWritev),
    Pselect6(Pselect6),
    Pselect6Time32(Pselect6Time32),
    Ptrace(Ptrace),
    Pwrite64(Pwrite64),
    Pwritev(Pwritev),
    Pwritev2(Pwritev2),
    Quotactl(Quotactl),
    Read(Read),
    Readahead(Readahead),
    Readlink(Readlink),
    Readlinkat(Readlinkat),
    Readv(Readv),
    Reboot(Reboot),
    Recv(Recv),
    Recvfrom(Recvfrom),
    Recvmmsg(Recvmmsg),
    RecvmmsgTime32(RecvmmsgTime32),
    Recvmsg(Recvmsg),
    RemapFilePages(RemapFilePages),
    Removexattr(Removexattr),
    Rename(Rename),
    Renameat(Renameat),
    Renameat2(Renameat2),
    RequestKey(RequestKey),
    RestartSyscall(RestartSyscall),
    RiscvFlushIcache(RiscvFlushIcache),
    Rmdir(Rmdir),
    Rseq(Rseq),
    RtSigaction(RtSigaction),
    RtSigpending(RtSigpending),
    RtSigprocmask(RtSigprocmask),
    RtSigqueueinfo(RtSigqueueinfo),
    RtSigreturn(RtSigreturn),
    RtSigsuspend(RtSigsuspend),
    RtSigtimedwait(RtSigtimedwait),
    RtSigtimedwaitTime32(RtSigtimedwaitTime32),
    RtTgsigqueueinfo(RtTgsigqueueinfo),
    Rtas(Rtas),
    S390GuardedStorage(S390GuardedStorage),
    S390Ipc(S390Ipc),
    S390PciMmioRead(S390PciMmioRead),
    S390PciMmioWrite(S390PciMmioWrite),
    S390Personality(S390Personality),
    S390RuntimeInstr(S390RuntimeInstr),
    S390Sthyi(S390Sthyi),
    SchedGetPriorityMax(SchedGetPriorityMax),
    SchedGetPriorityMin(SchedGetPriorityMin),
    SchedGetaffinity(SchedGetaffinity),
    SchedGetattr(SchedGetattr),
    SchedGetparam(SchedGetparam),
    SchedGetscheduler(SchedGetscheduler),
    SchedRrGetInterval(SchedRrGetInterval),
    SchedRrGetIntervalTime32(SchedRrGetIntervalTime32),
    SchedSetaffinity(SchedSetaffinity),
    SchedSetattr(SchedSetattr),
    SchedSetparam(SchedSetparam),
    SchedSetscheduler(SchedSetscheduler),
    SchedYield(SchedYield),
    Seccomp(Seccomp),
    Select(Select),
    Semctl(Semctl),
    Semget(Semget),
    Semop(Semop),
    Semtimedop(Semtimedop),
    SemtimedopTime32(SemtimedopTime32),
    Send(Send),
    Sendfile(Sendfile),
    Sendfile64(Sendfile64),
    Sendmmsg(Sendmmsg),
    Sendmsg(Sendmsg),
    Sendto(Sendto),
    SetMempolicy(SetMempolicy),
    SetRobustList(SetRobustList),
    SetThreadArea(SetThreadArea),
    SetTidAddress(SetTidAddress),
    Setdomainname(Setdomainname),
    Setfsgid(Setfsgid),
    Setfsgid16(Setfsgid16),
    Setfsuid(Setfsuid),
    Setfsuid16(Setfsuid16),
    Setgid(Setgid),
    Setgid16(Setgid16),
    Setgroups(Setgroups),
    Setgroups16(Setgroups16),
    Sethae(Sethae),
    Sethostname(Sethostname),
    Setitimer(Setitimer),
    Setns(Setns),
    Setpgid(Setpgid),
    Setpriority(Setpriority),
    Setregid(Setregid),
    Setregid16(Setregid16),
    Setresgid(Setresgid),
    Setresgid16(Setresgid16),
    Setresuid(Setresuid),
    Setresuid16(Setresuid16),
    Setreuid(Setreuid),
    Setreuid16(Setreuid16),
    Setrlimit(Setrlimit),
    Setsid(Setsid),
    Setsockopt(Setsockopt),
    Settimeofday(Settimeofday),
    Setuid(Setuid),
    Setuid16(Setuid16),
    Setxattr(Setxattr),
    Sgetmask(Sgetmask),
    Shmat(Shmat),
    Shmctl(Shmctl),
    Shmdt(Shmdt),
    Shmget(Shmget),
    Shutdown(Shutdown),
    Sigaction(Sigaction),
    Sigaltstack(Sigaltstack),
    Signal(Signal),
    Signalfd(Signalfd),
    Signalfd4(Signalfd4),
    Sigpending(Sigpending),
    Sigprocmask(Sigprocmask),
    Sigreturn(Sigreturn),
    Sigsuspend(Sigsuspend),
    Socket(Socket),
    Socketcall(Socketcall),
    Socketpair(Socketpair),
    Sparc64Personality(Sparc64Personality),
    SparcAdjtimex(SparcAdjtimex),
    SparcClockAdjtime(SparcClockAdjtime),
    SparcIpc(SparcIpc),
    SparcPipe(SparcPipe),
    SparcRemapFilePages(SparcRemapFilePages),
    SparcSigaction(SparcSigaction),
    Splice(Splice),
    SpuCreate(SpuCreate),
    SpuRun(SpuRun),
    Ssetmask(Ssetmask),
    Stat(Stat),
    Stat64(Stat64),
    Statfs(Statfs),
    Statfs64(Statfs64),
    Statx(Statx),
    Stime(Stime),
    Stime32(Stime32),
    SubpageProt(SubpageProt),
    Swapcontext(Swapcontext),
    Swapoff(Swapoff),
    Swapon(Swapon),
    SwitchEndian(SwitchEndian),
    Symlink(Symlink),
    Symlinkat(Symlinkat),
    Sync(Sync),
    SyncFileRange(SyncFileRange),
    SyncFileRange2(SyncFileRange2),
    Syncfs(Syncfs),
    Sysctl(Sysctl),
    Sysfs(Sysfs),
    Sysinfo(Sysinfo),
    Syslog(Syslog),
    Sysmips(Sysmips),
    Tee(Tee),
    Tgkill(Tgkill),
    Time(Time),
    Time32(Time32),
    TimerCreate(TimerCreate),
    TimerDelete(TimerDelete),
    TimerGetoverrun(TimerGetoverrun),
    TimerGettime(TimerGettime),
    TimerGettime32(TimerGettime32),
    TimerSettime(TimerSettime),
    TimerSettime32(TimerSettime32),
    TimerfdCreate(TimerfdCreate),
    TimerfdGettime(TimerfdGettime),
    TimerfdGettime32(TimerfdGettime32),
    TimerfdSettime(TimerfdSettime),
    TimerfdSettime32(TimerfdSettime32),
    Times(Times),
    Tkill(Tkill),
    Truncate(Truncate),
    Truncate64(Truncate64),
    Umask(Umask),
    Umount(Umount),
    Uname(Uname),
    Unlink(Unlink),
    Unlinkat(Unlinkat),
    Unshare(Unshare),
    Uselib(Uselib),
    Userfaultfd(Userfaultfd),
    Ustat(Ustat),
    Utime(Utime),
    Utime32(Utime32),
    Utimensat(Utimensat),
    UtimensatTime32(UtimensatTime32),
    Utimes(Utimes),
    UtimesTime32(UtimesTime32),
    UtrapInstall(UtrapInstall),
    Vfork(Vfork),
    Vhangup(Vhangup),
    Vm86(Vm86),
    Vm86old(Vm86old),
    Vmsplice(Vmsplice),
    Wait4(Wait4),
    Waitid(Waitid),
    Waitpid(Waitpid),
    Write(Write),
    Writev(Writev),
}

#[derive(Debug)]
pub enum SyscallExit {
    SyscallGood(SyscallReturn),
    SyscallError(OsError),
}

impl SyscallExit {
    pub fn into_result(self) -> Result<SyscallReturn, OsError> {
        match self {
            SyscallExit::SyscallGood(x) => Ok(x),
            SyscallExit::SyscallError(e) => Err(e),
        }
    }
}

#[derive(Debug)]
pub enum SyscallReturn {
    Accept(AcceptReturn),
    Accept4(Accept4Return),
    Access(AccessReturn),
    Acct(AcctReturn),
    AddKey(AddKeyReturn),
    Adjtimex(AdjtimexReturn),
    AdjtimexTime32(AdjtimexTime32Return),
    Alarm(AlarmReturn),
    AlphaPipe(AlphaPipeReturn),
    ArcGettls(ArcGettlsReturn),
    ArcSettls(ArcSettlsReturn),
    ArcUsrCmpxchg(ArcUsrCmpxchgReturn),
    Arch32Ftruncate64(Arch32Ftruncate64Return),
    Arch32Llseek(Arch32LlseekReturn),
    Arch32Personality(Arch32PersonalityReturn),
    Arch32Pread(Arch32PreadReturn),
    Arch32Pwrite(Arch32PwriteReturn),
    Arch32Sigaction(Arch32SigactionReturn),
    Arch32Truncate64(Arch32Truncate64Return),
    Arch64Mremap(Arch64MremapReturn),
    Arch64Munmap(Arch64MunmapReturn),
    ArchPrctl(ArchPrctlReturn),
    Arm64Personality(Arm64PersonalityReturn),
    Bdflush(BdflushReturn),
    Bind(BindReturn),
    Bpf(BpfReturn),
    Brk(BrkReturn),
    Cachectl(CachectlReturn),
    Cacheflush(CacheflushReturn),
    Capget(CapgetReturn),
    Capset(CapsetReturn),
    Chdir(ChdirReturn),
    Chmod(ChmodReturn),
    Chown(ChownReturn),
    Chown16(Chown16Return),
    Chroot(ChrootReturn),
    ClockAdjtime(ClockAdjtimeReturn),
    ClockAdjtime32(ClockAdjtime32Return),
    ClockGetres(ClockGetresReturn),
    ClockGetresTime32(ClockGetresTime32Return),
    ClockGettime(ClockGettimeReturn),
    ClockGettime32(ClockGettime32Return),
    ClockNanosleep(ClockNanosleepReturn),
    ClockNanosleepTime32(ClockNanosleepTime32Return),
    ClockSettime(ClockSettimeReturn),
    ClockSettime32(ClockSettime32Return),
    Clone(CloneReturn),
    Clone3(Clone3Return),
    Close(CloseReturn),
    Connect(ConnectReturn),
    CopyFileRange(CopyFileRangeReturn),
    Creat(CreatReturn),
    CskyFadvise6464(CskyFadvise6464Return),
    DebugSetcontext(DebugSetcontextReturn),
    DeleteModule(DeleteModuleReturn),
    Dup(DupReturn),
    Dup2(Dup2Return),
    Dup3(Dup3Return),
    EpollCreate(EpollCreateReturn),
    EpollCreate1(EpollCreate1Return),
    EpollCtl(EpollCtlReturn),
    EpollPwait(EpollPwaitReturn),
    EpollWait(EpollWaitReturn),
    Eventfd(EventfdReturn),
    Eventfd2(Eventfd2Return),
    Execve(ExecveReturn),
    Execveat(ExecveatReturn),
    Exit(ExitReturn),
    ExitGroup(ExitGroupReturn),
    Faccessat(FaccessatReturn),
    Fadvise64(Fadvise64Return),
    Fadvise6464(Fadvise6464Return),
    Fadvise6464Wrapper(Fadvise6464WrapperReturn),
    Fallocate(FallocateReturn),
    FanotifyInit(FanotifyInitReturn),
    FanotifyMark(FanotifyMarkReturn),
    Fchdir(FchdirReturn),
    Fchmod(FchmodReturn),
    Fchmodat(FchmodatReturn),
    Fchown(FchownReturn),
    Fchown16(Fchown16Return),
    Fchownat(FchownatReturn),
    Fcntl(FcntlReturn),
    Fcntl64(Fcntl64Return),
    Fdatasync(FdatasyncReturn),
    Fgetxattr(FgetxattrReturn),
    FinitModule(FinitModuleReturn),
    Flistxattr(FlistxattrReturn),
    Flock(FlockReturn),
    Fork(ForkReturn),
    FpUdfiexCrtl(FpUdfiexCrtlReturn),
    Fremovexattr(FremovexattrReturn),
    Fsconfig(FsconfigReturn),
    Fsetxattr(FsetxattrReturn),
    Fsmount(FsmountReturn),
    Fsopen(FsopenReturn),
    Fspick(FspickReturn),
    Fstat(FstatReturn),
    Fstat64(Fstat64Return),
    Fstatat64(Fstatat64Return),
    Fstatfs(FstatfsReturn),
    Fstatfs64(Fstatfs64Return),
    Fsync(FsyncReturn),
    Ftruncate(FtruncateReturn),
    Ftruncate64(Ftruncate64Return),
    Futex(FutexReturn),
    FutexTime32(FutexTime32Return),
    Futimesat(FutimesatReturn),
    FutimesatTime32(FutimesatTime32Return),
    GetMempolicy(GetMempolicyReturn),
    GetRobustList(GetRobustListReturn),
    GetThreadArea(GetThreadAreaReturn),
    Getcpu(GetcpuReturn),
    Getcwd(GetcwdReturn),
    Getdents(GetdentsReturn),
    Getdents64(Getdents64Return),
    Getdomainname(GetdomainnameReturn),
    Getdtablesize(GetdtablesizeReturn),
    Getegid(GetegidReturn),
    Getegid16(Getegid16Return),
    Geteuid(GeteuidReturn),
    Geteuid16(Geteuid16Return),
    Getgid(GetgidReturn),
    Getgid16(Getgid16Return),
    Getgroups(GetgroupsReturn),
    Getgroups16(Getgroups16Return),
    Gethostname(GethostnameReturn),
    Getitimer(GetitimerReturn),
    Getpagesize(GetpagesizeReturn),
    Getpeername(GetpeernameReturn),
    Getpgid(GetpgidReturn),
    Getpgrp(GetpgrpReturn),
    Getpid(GetpidReturn),
    Getppid(GetppidReturn),
    Getpriority(GetpriorityReturn),
    Getrandom(GetrandomReturn),
    Getresgid(GetresgidReturn),
    Getresgid16(Getresgid16Return),
    Getresuid(GetresuidReturn),
    Getresuid16(Getresuid16Return),
    Getrlimit(GetrlimitReturn),
    Getrusage(GetrusageReturn),
    Getsid(GetsidReturn),
    Getsockname(GetsocknameReturn),
    Getsockopt(GetsockoptReturn),
    Gettid(GettidReturn),
    Gettimeofday(GettimeofdayReturn),
    Getuid(GetuidReturn),
    Getuid16(Getuid16Return),
    Getxattr(GetxattrReturn),
    Getxgid(GetxgidReturn),
    Getxpid(GetxpidReturn),
    Getxuid(GetxuidReturn),
    InitModule(InitModuleReturn),
    InotifyAddWatch(InotifyAddWatchReturn),
    InotifyInit(InotifyInitReturn),
    InotifyInit1(InotifyInit1Return),
    InotifyRmWatch(InotifyRmWatchReturn),
    IoCancel(IoCancelReturn),
    IoDestroy(IoDestroyReturn),
    IoGetevents(IoGeteventsReturn),
    IoGeteventsTime32(IoGeteventsTime32Return),
    IoPgetevents(IoPgeteventsReturn),
    IoPgeteventsTime32(IoPgeteventsTime32Return),
    IoSetup(IoSetupReturn),
    IoSubmit(IoSubmitReturn),
    IoUringEnter(IoUringEnterReturn),
    IoUringRegister(IoUringRegisterReturn),
    IoUringSetup(IoUringSetupReturn),
    Ioctl(IoctlReturn),
    Ioperm(IopermReturn),
    Iopl(IoplReturn),
    IoprioGet(IoprioGetReturn),
    IoprioSet(IoprioSetReturn),
    Ipc(IpcReturn),
    Kcmp(KcmpReturn),
    KernFeatures(KernFeaturesReturn),
    KexecFileLoad(KexecFileLoadReturn),
    KexecLoad(KexecLoadReturn),
    Keyctl(KeyctlReturn),
    Kill(KillReturn),
    Lchown(LchownReturn),
    Lchown16(Lchown16Return),
    Lgetxattr(LgetxattrReturn),
    Link(LinkReturn),
    Linkat(LinkatReturn),
    Listen(ListenReturn),
    Listxattr(ListxattrReturn),
    Llistxattr(LlistxattrReturn),
    Llseek(LlseekReturn),
    LookupDcookie(LookupDcookieReturn),
    Lremovexattr(LremovexattrReturn),
    Lseek(LseekReturn),
    Lsetxattr(LsetxattrReturn),
    Lstat(LstatReturn),
    Lstat64(Lstat64Return),
    Madvise(MadviseReturn),
    Mbind(MbindReturn),
    Membarrier(MembarrierReturn),
    MemfdCreate(MemfdCreateReturn),
    MemoryOrdering(MemoryOrderingReturn),
    MigratePages(MigratePagesReturn),
    Mincore(MincoreReturn),
    MipsMmap(MipsMmapReturn),
    MipsMmap2(MipsMmap2Return),
    Mkdir(MkdirReturn),
    Mkdirat(MkdiratReturn),
    Mknod(MknodReturn),
    Mknodat(MknodatReturn),
    Mlock(MlockReturn),
    Mlock2(Mlock2Return),
    Mlockall(MlockallReturn),
    Mmap(MmapReturn),
    Mmap2(Mmap2Return),
    MmapPgoff(MmapPgoffReturn),
    ModifyLdt(ModifyLdtReturn),
    Mount(MountReturn),
    MoveMount(MoveMountReturn),
    MovePages(MovePagesReturn),
    Mprotect(MprotectReturn),
    MqGetsetattr(MqGetsetattrReturn),
    MqNotify(MqNotifyReturn),
    MqOpen(MqOpenReturn),
    MqTimedreceive(MqTimedreceiveReturn),
    MqTimedreceiveTime32(MqTimedreceiveTime32Return),
    MqTimedsend(MqTimedsendReturn),
    MqTimedsendTime32(MqTimedsendTime32Return),
    MqUnlink(MqUnlinkReturn),
    Mremap(MremapReturn),
    Msgctl(MsgctlReturn),
    Msgget(MsggetReturn),
    Msgrcv(MsgrcvReturn),
    Msgsnd(MsgsndReturn),
    Msync(MsyncReturn),
    Munlock(MunlockReturn),
    Munlockall(MunlockallReturn),
    Munmap(MunmapReturn),
    NameToHandleAt(NameToHandleAtReturn),
    Nanosleep(NanosleepReturn),
    NanosleepTime32(NanosleepTime32Return),
    Newfstat(NewfstatReturn),
    Newfstatat(NewfstatatReturn),
    Newlstat(NewlstatReturn),
    Newstat(NewstatReturn),
    Newuname(NewunameReturn),
    NiSyscall(NiSyscallReturn),
    Nice(NiceReturn),
    NisSyscall(NisSyscallReturn),
    OldAdjtimex(OldAdjtimexReturn),
    OldGetrlimit(OldGetrlimitReturn),
    OldMmap(OldMmapReturn),
    OldMsgctl(OldMsgctlReturn),
    OldReaddir(OldReaddirReturn),
    OldSelect(OldSelectReturn),
    OldSemctl(OldSemctlReturn),
    OldShmctl(OldShmctlReturn),
    Oldumount(OldumountReturn),
    Olduname(OldunameReturn),
    Open(OpenReturn),
    OpenByHandleAt(OpenByHandleAtReturn),
    OpenTree(OpenTreeReturn),
    Openat(OpenatReturn),
    Openat2(Openat2Return),
    OsfBrk(OsfBrkReturn),
    OsfFstat(OsfFstatReturn),
    OsfFstatfs(OsfFstatfsReturn),
    OsfFstatfs64(OsfFstatfs64Return),
    OsfGetdirentries(OsfGetdirentriesReturn),
    OsfGetdomainname(OsfGetdomainnameReturn),
    OsfGetpriority(OsfGetpriorityReturn),
    OsfGetrusage(OsfGetrusageReturn),
    OsfGetsysinfo(OsfGetsysinfoReturn),
    OsfGettimeofday(OsfGettimeofdayReturn),
    OsfLstat(OsfLstatReturn),
    OsfMmap(OsfMmapReturn),
    OsfMount(OsfMountReturn),
    OsfProplistSyscall(OsfProplistSyscallReturn),
    OsfReadv(OsfReadvReturn),
    OsfSelect(OsfSelectReturn),
    OsfSetProgramAttributes(OsfSetProgramAttributesReturn),
    OsfSetsysinfo(OsfSetsysinfoReturn),
    OsfSettimeofday(OsfSettimeofdayReturn),
    OsfSigaction(OsfSigactionReturn),
    OsfSigprocmask(OsfSigprocmaskReturn),
    OsfSigstack(OsfSigstackReturn),
    OsfStat(OsfStatReturn),
    OsfStatfs(OsfStatfsReturn),
    OsfStatfs64(OsfStatfs64Return),
    OsfSysinfo(OsfSysinfoReturn),
    OsfUsleepThread(OsfUsleepThreadReturn),
    OsfUtimes(OsfUtimesReturn),
    OsfUtsname(OsfUtsnameReturn),
    OsfWait4(OsfWait4Return),
    OsfWritev(OsfWritevReturn),
    Pause(PauseReturn),
    PciconfigIobase(PciconfigIobaseReturn),
    PciconfigRead(PciconfigReadReturn),
    PciconfigWrite(PciconfigWriteReturn),
    PerfEventOpen(PerfEventOpenReturn),
    Personality(PersonalityReturn),
    PidfdGetfd(PidfdGetfdReturn),
    PidfdOpen(PidfdOpenReturn),
    PidfdSendSignal(PidfdSendSignalReturn),
    Pipe(PipeReturn),
    Pipe2(Pipe2Return),
    PivotRoot(PivotRootReturn),
    PkeyAlloc(PkeyAllocReturn),
    PkeyFree(PkeyFreeReturn),
    PkeyMprotect(PkeyMprotectReturn),
    Poll(PollReturn),
    Ppoll(PpollReturn),
    PpollTime32(PpollTime32Return),
    Prctl(PrctlReturn),
    Pread64(Pread64Return),
    Preadv(PreadvReturn),
    Preadv2(Preadv2Return),
    Prlimit64(Prlimit64Return),
    ProcessVmReadv(ProcessVmReadvReturn),
    ProcessVmWritev(ProcessVmWritevReturn),
    Pselect6(Pselect6Return),
    Pselect6Time32(Pselect6Time32Return),
    Ptrace(PtraceReturn),
    Pwrite64(Pwrite64Return),
    Pwritev(PwritevReturn),
    Pwritev2(Pwritev2Return),
    Quotactl(QuotactlReturn),
    Read(ReadReturn),
    Readahead(ReadaheadReturn),
    Readlink(ReadlinkReturn),
    Readlinkat(ReadlinkatReturn),
    Readv(ReadvReturn),
    Reboot(RebootReturn),
    Recv(RecvReturn),
    Recvfrom(RecvfromReturn),
    Recvmmsg(RecvmmsgReturn),
    RecvmmsgTime32(RecvmmsgTime32Return),
    Recvmsg(RecvmsgReturn),
    RemapFilePages(RemapFilePagesReturn),
    Removexattr(RemovexattrReturn),
    Rename(RenameReturn),
    Renameat(RenameatReturn),
    Renameat2(Renameat2Return),
    RequestKey(RequestKeyReturn),
    RestartSyscall(RestartSyscallReturn),
    RiscvFlushIcache(RiscvFlushIcacheReturn),
    Rmdir(RmdirReturn),
    Rseq(RseqReturn),
    RtSigaction(RtSigactionReturn),
    RtSigpending(RtSigpendingReturn),
    RtSigprocmask(RtSigprocmaskReturn),
    RtSigqueueinfo(RtSigqueueinfoReturn),
    RtSigreturn(RtSigreturnReturn),
    RtSigsuspend(RtSigsuspendReturn),
    RtSigtimedwait(RtSigtimedwaitReturn),
    RtSigtimedwaitTime32(RtSigtimedwaitTime32Return),
    RtTgsigqueueinfo(RtTgsigqueueinfoReturn),
    Rtas(RtasReturn),
    S390GuardedStorage(S390GuardedStorageReturn),
    S390Ipc(S390IpcReturn),
    S390PciMmioRead(S390PciMmioReadReturn),
    S390PciMmioWrite(S390PciMmioWriteReturn),
    S390Personality(S390PersonalityReturn),
    S390RuntimeInstr(S390RuntimeInstrReturn),
    S390Sthyi(S390SthyiReturn),
    SchedGetPriorityMax(SchedGetPriorityMaxReturn),
    SchedGetPriorityMin(SchedGetPriorityMinReturn),
    SchedGetaffinity(SchedGetaffinityReturn),
    SchedGetattr(SchedGetattrReturn),
    SchedGetparam(SchedGetparamReturn),
    SchedGetscheduler(SchedGetschedulerReturn),
    SchedRrGetInterval(SchedRrGetIntervalReturn),
    SchedRrGetIntervalTime32(SchedRrGetIntervalTime32Return),
    SchedSetaffinity(SchedSetaffinityReturn),
    SchedSetattr(SchedSetattrReturn),
    SchedSetparam(SchedSetparamReturn),
    SchedSetscheduler(SchedSetschedulerReturn),
    SchedYield(SchedYieldReturn),
    Seccomp(SeccompReturn),
    Select(SelectReturn),
    Semctl(SemctlReturn),
    Semget(SemgetReturn),
    Semop(SemopReturn),
    Semtimedop(SemtimedopReturn),
    SemtimedopTime32(SemtimedopTime32Return),
    Send(SendReturn),
    Sendfile(SendfileReturn),
    Sendfile64(Sendfile64Return),
    Sendmmsg(SendmmsgReturn),
    Sendmsg(SendmsgReturn),
    Sendto(SendtoReturn),
    SetMempolicy(SetMempolicyReturn),
    SetRobustList(SetRobustListReturn),
    SetThreadArea(SetThreadAreaReturn),
    SetTidAddress(SetTidAddressReturn),
    Setdomainname(SetdomainnameReturn),
    Setfsgid(SetfsgidReturn),
    Setfsgid16(Setfsgid16Return),
    Setfsuid(SetfsuidReturn),
    Setfsuid16(Setfsuid16Return),
    Setgid(SetgidReturn),
    Setgid16(Setgid16Return),
    Setgroups(SetgroupsReturn),
    Setgroups16(Setgroups16Return),
    Sethae(SethaeReturn),
    Sethostname(SethostnameReturn),
    Setitimer(SetitimerReturn),
    Setns(SetnsReturn),
    Setpgid(SetpgidReturn),
    Setpriority(SetpriorityReturn),
    Setregid(SetregidReturn),
    Setregid16(Setregid16Return),
    Setresgid(SetresgidReturn),
    Setresgid16(Setresgid16Return),
    Setresuid(SetresuidReturn),
    Setresuid16(Setresuid16Return),
    Setreuid(SetreuidReturn),
    Setreuid16(Setreuid16Return),
    Setrlimit(SetrlimitReturn),
    Setsid(SetsidReturn),
    Setsockopt(SetsockoptReturn),
    Settimeofday(SettimeofdayReturn),
    Setuid(SetuidReturn),
    Setuid16(Setuid16Return),
    Setxattr(SetxattrReturn),
    Sgetmask(SgetmaskReturn),
    Shmat(ShmatReturn),
    Shmctl(ShmctlReturn),
    Shmdt(ShmdtReturn),
    Shmget(ShmgetReturn),
    Shutdown(ShutdownReturn),
    Sigaction(SigactionReturn),
    Sigaltstack(SigaltstackReturn),
    Signal(SignalReturn),
    Signalfd(SignalfdReturn),
    Signalfd4(Signalfd4Return),
    Sigpending(SigpendingReturn),
    Sigprocmask(SigprocmaskReturn),
    Sigreturn(SigreturnReturn),
    Sigsuspend(SigsuspendReturn),
    Socket(SocketReturn),
    Socketcall(SocketcallReturn),
    Socketpair(SocketpairReturn),
    Sparc64Personality(Sparc64PersonalityReturn),
    SparcAdjtimex(SparcAdjtimexReturn),
    SparcClockAdjtime(SparcClockAdjtimeReturn),
    SparcIpc(SparcIpcReturn),
    SparcPipe(SparcPipeReturn),
    SparcRemapFilePages(SparcRemapFilePagesReturn),
    SparcSigaction(SparcSigactionReturn),
    Splice(SpliceReturn),
    SpuCreate(SpuCreateReturn),
    SpuRun(SpuRunReturn),
    Ssetmask(SsetmaskReturn),
    Stat(StatReturn),
    Stat64(Stat64Return),
    Statfs(StatfsReturn),
    Statfs64(Statfs64Return),
    Statx(StatxReturn),
    Stime(StimeReturn),
    Stime32(Stime32Return),
    SubpageProt(SubpageProtReturn),
    Swapcontext(SwapcontextReturn),
    Swapoff(SwapoffReturn),
    Swapon(SwaponReturn),
    SwitchEndian(SwitchEndianReturn),
    Symlink(SymlinkReturn),
    Symlinkat(SymlinkatReturn),
    Sync(SyncReturn),
    SyncFileRange(SyncFileRangeReturn),
    SyncFileRange2(SyncFileRange2Return),
    Syncfs(SyncfsReturn),
    Sysctl(SysctlReturn),
    Sysfs(SysfsReturn),
    Sysinfo(SysinfoReturn),
    Syslog(SyslogReturn),
    Sysmips(SysmipsReturn),
    Tee(TeeReturn),
    Tgkill(TgkillReturn),
    Time(TimeReturn),
    Time32(Time32Return),
    TimerCreate(TimerCreateReturn),
    TimerDelete(TimerDeleteReturn),
    TimerGetoverrun(TimerGetoverrunReturn),
    TimerGettime(TimerGettimeReturn),
    TimerGettime32(TimerGettime32Return),
    TimerSettime(TimerSettimeReturn),
    TimerSettime32(TimerSettime32Return),
    TimerfdCreate(TimerfdCreateReturn),
    TimerfdGettime(TimerfdGettimeReturn),
    TimerfdGettime32(TimerfdGettime32Return),
    TimerfdSettime(TimerfdSettimeReturn),
    TimerfdSettime32(TimerfdSettime32Return),
    Times(TimesReturn),
    Tkill(TkillReturn),
    Truncate(TruncateReturn),
    Truncate64(Truncate64Return),
    Umask(UmaskReturn),
    Umount(UmountReturn),
    Uname(UnameReturn),
    Unlink(UnlinkReturn),
    Unlinkat(UnlinkatReturn),
    Unshare(UnshareReturn),
    Uselib(UselibReturn),
    Userfaultfd(UserfaultfdReturn),
    Ustat(UstatReturn),
    Utime(UtimeReturn),
    Utime32(Utime32Return),
    Utimensat(UtimensatReturn),
    UtimensatTime32(UtimensatTime32Return),
    Utimes(UtimesReturn),
    UtimesTime32(UtimesTime32Return),
    UtrapInstall(UtrapInstallReturn),
    Vfork(VforkReturn),
    Vhangup(VhangupReturn),
    Vm86(Vm86Return),
    Vm86old(Vm86oldReturn),
    Vmsplice(VmspliceReturn),
    Wait4(Wait4Return),
    Waitid(WaitidReturn),
    Waitpid(WaitpidReturn),
    Write(WriteReturn),
    Writev(WritevReturn),
}

impl SyscallEnter {
    pub fn from_args_x86_64(
        syscall_nr: u64,
        args: [u64; 6],
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        let enter_call = match syscall_nr {
            0 => SyscallEnter::Read(Read::from_args(args, process)?),
            1 => SyscallEnter::Write(Write::from_args(args, process)?),
            2 => SyscallEnter::Open(Open::from_args(args, process)?),
            3 => SyscallEnter::Close(Close::from_args(args, process)?),
            4 => SyscallEnter::Stat(Stat::from_args(args, process)?),
            5 => SyscallEnter::Fstat(Fstat::from_args(args, process)?),
            6 => SyscallEnter::Lstat(Lstat::from_args(args, process)?),
            7 => SyscallEnter::Poll(Poll::from_args(args, process)?),
            8 => SyscallEnter::Lseek(Lseek::from_args(args, process)?),
            9 => SyscallEnter::Mmap(Mmap::from_args(args, process)?),
            10 => SyscallEnter::Mprotect(Mprotect::from_args(args, process)?),
            11 => SyscallEnter::Munmap(Munmap::from_args(args, process)?),
            12 => SyscallEnter::Brk(Brk::from_args(args, process)?),
            13 => SyscallEnter::RtSigaction(RtSigaction::from_args(args, process)?),
            14 => SyscallEnter::RtSigprocmask(RtSigprocmask::from_args(args, process)?),
            15 => SyscallEnter::RtSigreturn(RtSigreturn::from_args(args, process)?),
            16 => SyscallEnter::Ioctl(Ioctl::from_args(args, process)?),
            17 => SyscallEnter::Pread64(Pread64::from_args(args, process)?),
            18 => SyscallEnter::Pwrite64(Pwrite64::from_args(args, process)?),
            19 => SyscallEnter::Readv(Readv::from_args(args, process)?),
            20 => SyscallEnter::Writev(Writev::from_args(args, process)?),
            21 => SyscallEnter::Access(Access::from_args(args, process)?),
            22 => SyscallEnter::Pipe(Pipe::from_args(args, process)?),
            23 => SyscallEnter::Select(Select::from_args(args, process)?),
            24 => SyscallEnter::SchedYield(SchedYield::from_args(args, process)?),
            25 => SyscallEnter::Mremap(Mremap::from_args(args, process)?),
            26 => SyscallEnter::Msync(Msync::from_args(args, process)?),
            27 => SyscallEnter::Mincore(Mincore::from_args(args, process)?),
            28 => SyscallEnter::Madvise(Madvise::from_args(args, process)?),
            29 => SyscallEnter::Shmget(Shmget::from_args(args, process)?),
            30 => SyscallEnter::Shmat(Shmat::from_args(args, process)?),
            31 => SyscallEnter::Shmctl(Shmctl::from_args(args, process)?),
            32 => SyscallEnter::Dup(Dup::from_args(args, process)?),
            33 => SyscallEnter::Dup2(Dup2::from_args(args, process)?),
            34 => SyscallEnter::Pause(Pause::from_args(args, process)?),
            35 => SyscallEnter::Nanosleep(Nanosleep::from_args(args, process)?),
            36 => SyscallEnter::Getitimer(Getitimer::from_args(args, process)?),
            37 => SyscallEnter::Alarm(Alarm::from_args(args, process)?),
            38 => SyscallEnter::Setitimer(Setitimer::from_args(args, process)?),
            39 => SyscallEnter::Getpid(Getpid::from_args(args, process)?),
            40 => SyscallEnter::Sendfile(Sendfile::from_args(args, process)?),
            41 => SyscallEnter::Socket(Socket::from_args(args, process)?),
            42 => SyscallEnter::Connect(Connect::from_args(args, process)?),
            43 => SyscallEnter::Accept(Accept::from_args(args, process)?),
            44 => SyscallEnter::Sendto(Sendto::from_args(args, process)?),
            45 => SyscallEnter::Recvfrom(Recvfrom::from_args(args, process)?),
            46 => SyscallEnter::Sendmsg(Sendmsg::from_args(args, process)?),
            47 => SyscallEnter::Recvmsg(Recvmsg::from_args(args, process)?),
            48 => SyscallEnter::Shutdown(Shutdown::from_args(args, process)?),
            49 => SyscallEnter::Bind(Bind::from_args(args, process)?),
            50 => SyscallEnter::Listen(Listen::from_args(args, process)?),
            51 => SyscallEnter::Getsockname(Getsockname::from_args(args, process)?),
            52 => SyscallEnter::Getpeername(Getpeername::from_args(args, process)?),
            53 => SyscallEnter::Socketpair(Socketpair::from_args(args, process)?),
            54 => SyscallEnter::Setsockopt(Setsockopt::from_args(args, process)?),
            55 => SyscallEnter::Getsockopt(Getsockopt::from_args(args, process)?),
            56 => SyscallEnter::Clone(Clone::from_args(args, process)?),
            57 => SyscallEnter::Fork(Fork::from_args(args, process)?),
            58 => SyscallEnter::Vfork(Vfork::from_args(args, process)?),
            59 => SyscallEnter::Execve(Execve::from_args(args, process)?),
            60 => SyscallEnter::Exit(Exit::from_args(args, process)?),
            61 => SyscallEnter::Wait4(Wait4::from_args(args, process)?),
            62 => SyscallEnter::Kill(Kill::from_args(args, process)?),
            63 => SyscallEnter::Uname(Uname::from_args(args, process)?),
            64 => SyscallEnter::Semget(Semget::from_args(args, process)?),
            65 => SyscallEnter::Semop(Semop::from_args(args, process)?),
            66 => SyscallEnter::Semctl(Semctl::from_args(args, process)?),
            67 => SyscallEnter::Shmdt(Shmdt::from_args(args, process)?),
            68 => SyscallEnter::Msgget(Msgget::from_args(args, process)?),
            69 => SyscallEnter::Msgsnd(Msgsnd::from_args(args, process)?),
            70 => SyscallEnter::Msgrcv(Msgrcv::from_args(args, process)?),
            71 => SyscallEnter::Msgctl(Msgctl::from_args(args, process)?),
            72 => SyscallEnter::Fcntl(Fcntl::from_args(args, process)?),
            73 => SyscallEnter::Flock(Flock::from_args(args, process)?),
            74 => SyscallEnter::Fsync(Fsync::from_args(args, process)?),
            75 => SyscallEnter::Fdatasync(Fdatasync::from_args(args, process)?),
            76 => SyscallEnter::Truncate(Truncate::from_args(args, process)?),
            77 => SyscallEnter::Ftruncate(Ftruncate::from_args(args, process)?),
            78 => SyscallEnter::Getdents(Getdents::from_args(args, process)?),
            79 => SyscallEnter::Getcwd(Getcwd::from_args(args, process)?),
            80 => SyscallEnter::Chdir(Chdir::from_args(args, process)?),
            81 => SyscallEnter::Fchdir(Fchdir::from_args(args, process)?),
            82 => SyscallEnter::Rename(Rename::from_args(args, process)?),
            83 => SyscallEnter::Mkdir(Mkdir::from_args(args, process)?),
            84 => SyscallEnter::Rmdir(Rmdir::from_args(args, process)?),
            85 => SyscallEnter::Creat(Creat::from_args(args, process)?),
            86 => SyscallEnter::Link(Link::from_args(args, process)?),
            87 => SyscallEnter::Unlink(Unlink::from_args(args, process)?),
            88 => SyscallEnter::Symlink(Symlink::from_args(args, process)?),
            89 => SyscallEnter::Readlink(Readlink::from_args(args, process)?),
            90 => SyscallEnter::Chmod(Chmod::from_args(args, process)?),
            91 => SyscallEnter::Fchmod(Fchmod::from_args(args, process)?),
            92 => SyscallEnter::Chown(Chown::from_args(args, process)?),
            93 => SyscallEnter::Fchown(Fchown::from_args(args, process)?),
            94 => SyscallEnter::Lchown(Lchown::from_args(args, process)?),
            95 => SyscallEnter::Umask(Umask::from_args(args, process)?),
            96 => SyscallEnter::Gettimeofday(Gettimeofday::from_args(args, process)?),
            97 => SyscallEnter::Getrlimit(Getrlimit::from_args(args, process)?),
            98 => SyscallEnter::Getrusage(Getrusage::from_args(args, process)?),
            99 => SyscallEnter::Sysinfo(Sysinfo::from_args(args, process)?),
            100 => SyscallEnter::Times(Times::from_args(args, process)?),
            101 => SyscallEnter::Ptrace(Ptrace::from_args(args, process)?),
            102 => SyscallEnter::Getuid(Getuid::from_args(args, process)?),
            103 => SyscallEnter::Syslog(Syslog::from_args(args, process)?),
            104 => SyscallEnter::Getgid(Getgid::from_args(args, process)?),
            105 => SyscallEnter::Setuid(Setuid::from_args(args, process)?),
            106 => SyscallEnter::Setgid(Setgid::from_args(args, process)?),
            107 => SyscallEnter::Geteuid(Geteuid::from_args(args, process)?),
            108 => SyscallEnter::Getegid(Getegid::from_args(args, process)?),
            109 => SyscallEnter::Setpgid(Setpgid::from_args(args, process)?),
            110 => SyscallEnter::Getppid(Getppid::from_args(args, process)?),
            111 => SyscallEnter::Getpgrp(Getpgrp::from_args(args, process)?),
            112 => SyscallEnter::Setsid(Setsid::from_args(args, process)?),
            113 => SyscallEnter::Setreuid(Setreuid::from_args(args, process)?),
            114 => SyscallEnter::Setregid(Setregid::from_args(args, process)?),
            115 => SyscallEnter::Getgroups(Getgroups::from_args(args, process)?),
            116 => SyscallEnter::Setgroups(Setgroups::from_args(args, process)?),
            117 => SyscallEnter::Setresuid(Setresuid::from_args(args, process)?),
            118 => SyscallEnter::Getresuid(Getresuid::from_args(args, process)?),
            119 => SyscallEnter::Setresgid(Setresgid::from_args(args, process)?),
            120 => SyscallEnter::Getresgid(Getresgid::from_args(args, process)?),
            121 => SyscallEnter::Getpgid(Getpgid::from_args(args, process)?),
            122 => SyscallEnter::Setfsuid(Setfsuid::from_args(args, process)?),
            123 => SyscallEnter::Setfsgid(Setfsgid::from_args(args, process)?),
            124 => SyscallEnter::Getsid(Getsid::from_args(args, process)?),
            125 => SyscallEnter::Capget(Capget::from_args(args, process)?),
            126 => SyscallEnter::Capset(Capset::from_args(args, process)?),
            127 => SyscallEnter::RtSigpending(RtSigpending::from_args(args, process)?),
            128 => SyscallEnter::RtSigtimedwait(RtSigtimedwait::from_args(args, process)?),
            129 => SyscallEnter::RtSigqueueinfo(RtSigqueueinfo::from_args(args, process)?),
            130 => SyscallEnter::RtSigsuspend(RtSigsuspend::from_args(args, process)?),
            131 => SyscallEnter::Sigaltstack(Sigaltstack::from_args(args, process)?),
            132 => SyscallEnter::Utime(Utime::from_args(args, process)?),
            133 => SyscallEnter::Mknod(Mknod::from_args(args, process)?),
            134 => SyscallEnter::Uselib(Uselib::from_args(args, process)?),
            135 => SyscallEnter::Personality(Personality::from_args(args, process)?),
            136 => SyscallEnter::Ustat(Ustat::from_args(args, process)?),
            137 => SyscallEnter::Statfs(Statfs::from_args(args, process)?),
            138 => SyscallEnter::Fstatfs(Fstatfs::from_args(args, process)?),
            139 => SyscallEnter::Sysfs(Sysfs::from_args(args, process)?),
            140 => SyscallEnter::Getpriority(Getpriority::from_args(args, process)?),
            141 => SyscallEnter::Setpriority(Setpriority::from_args(args, process)?),
            142 => SyscallEnter::SchedSetparam(SchedSetparam::from_args(args, process)?),
            143 => SyscallEnter::SchedGetparam(SchedGetparam::from_args(args, process)?),
            144 => SyscallEnter::SchedSetscheduler(SchedSetscheduler::from_args(args, process)?),
            145 => SyscallEnter::SchedGetscheduler(SchedGetscheduler::from_args(args, process)?),
            146 => {
                SyscallEnter::SchedGetPriorityMax(SchedGetPriorityMax::from_args(args, process)?)
            }
            147 => {
                SyscallEnter::SchedGetPriorityMin(SchedGetPriorityMin::from_args(args, process)?)
            }
            148 => SyscallEnter::SchedRrGetInterval(SchedRrGetInterval::from_args(args, process)?),
            149 => SyscallEnter::Mlock(Mlock::from_args(args, process)?),
            150 => SyscallEnter::Munlock(Munlock::from_args(args, process)?),
            151 => SyscallEnter::Mlockall(Mlockall::from_args(args, process)?),
            152 => SyscallEnter::Munlockall(Munlockall::from_args(args, process)?),
            153 => SyscallEnter::Vhangup(Vhangup::from_args(args, process)?),
            154 => SyscallEnter::ModifyLdt(ModifyLdt::from_args(args, process)?),
            155 => SyscallEnter::PivotRoot(PivotRoot::from_args(args, process)?),
            156 => SyscallEnter::Sysctl(Sysctl::from_args(args, process)?),
            157 => SyscallEnter::Prctl(Prctl::from_args(args, process)?),
            158 => SyscallEnter::ArchPrctl(ArchPrctl::from_args(args, process)?),
            159 => SyscallEnter::Adjtimex(Adjtimex::from_args(args, process)?),
            160 => SyscallEnter::Setrlimit(Setrlimit::from_args(args, process)?),
            161 => SyscallEnter::Chroot(Chroot::from_args(args, process)?),
            162 => SyscallEnter::Sync(Sync::from_args(args, process)?),
            163 => SyscallEnter::Acct(Acct::from_args(args, process)?),
            164 => SyscallEnter::Settimeofday(Settimeofday::from_args(args, process)?),
            165 => SyscallEnter::Mount(Mount::from_args(args, process)?),
            166 => SyscallEnter::Umount(Umount::from_args(args, process)?),
            167 => SyscallEnter::Swapon(Swapon::from_args(args, process)?),
            168 => SyscallEnter::Swapoff(Swapoff::from_args(args, process)?),
            169 => SyscallEnter::Reboot(Reboot::from_args(args, process)?),
            170 => SyscallEnter::Sethostname(Sethostname::from_args(args, process)?),
            171 => SyscallEnter::Setdomainname(Setdomainname::from_args(args, process)?),
            172 => SyscallEnter::Iopl(Iopl::from_args(args, process)?),
            173 => SyscallEnter::Ioperm(Ioperm::from_args(args, process)?),
            // 174 => SyscallEnter::CreateModule(CreateModule::from_args(args, process)?),
            175 => SyscallEnter::InitModule(InitModule::from_args(args, process)?),
            176 => SyscallEnter::DeleteModule(DeleteModule::from_args(args, process)?),
            // 177 => SyscallEnter::GetKernelSyms(GetKernelSyms::from_args(args, process)?),
            // 178 => SyscallEnter::QueryModule(QueryModule::from_args(args, process)?),
            179 => SyscallEnter::Quotactl(Quotactl::from_args(args, process)?),
            // 180 => SyscallEnter::Nfsservctl(Nfsservctl::from_args(args, process)?),
            // 181 => SyscallEnter::Getpmsg(Getpmsg::from_args(args, process)?),
            // 182 => SyscallEnter::Putpmsg(Putpmsg::from_args(args, process)?),
            // 183 => SyscallEnter::AfsSyscall(AfsSyscall::from_args(args, process)?),
            // 184 => SyscallEnter::Tuxcall(Tuxcall::from_args(args, process)?),
            //185 => SyscallEnter::Security(Security::from_args(args, process)?),
            186 => SyscallEnter::Gettid(Gettid::from_args(args, process)?),
            187 => SyscallEnter::Readahead(Readahead::from_args(args, process)?),
            188 => SyscallEnter::Setxattr(Setxattr::from_args(args, process)?),
            189 => SyscallEnter::Lsetxattr(Lsetxattr::from_args(args, process)?),
            190 => SyscallEnter::Fsetxattr(Fsetxattr::from_args(args, process)?),
            191 => SyscallEnter::Getxattr(Getxattr::from_args(args, process)?),
            192 => SyscallEnter::Lgetxattr(Lgetxattr::from_args(args, process)?),
            193 => SyscallEnter::Fgetxattr(Fgetxattr::from_args(args, process)?),
            194 => SyscallEnter::Listxattr(Listxattr::from_args(args, process)?),
            195 => SyscallEnter::Llistxattr(Llistxattr::from_args(args, process)?),
            196 => SyscallEnter::Flistxattr(Flistxattr::from_args(args, process)?),
            197 => SyscallEnter::Removexattr(Removexattr::from_args(args, process)?),
            198 => SyscallEnter::Lremovexattr(Lremovexattr::from_args(args, process)?),
            199 => SyscallEnter::Fremovexattr(Fremovexattr::from_args(args, process)?),
            200 => SyscallEnter::Tkill(Tkill::from_args(args, process)?),
            201 => SyscallEnter::Time(Time::from_args(args, process)?),
            202 => SyscallEnter::Futex(Futex::from_args(args, process)?),
            203 => SyscallEnter::SchedSetaffinity(SchedSetaffinity::from_args(args, process)?),
            204 => SyscallEnter::SchedGetaffinity(SchedGetaffinity::from_args(args, process)?),
            205 => SyscallEnter::SetThreadArea(SetThreadArea::from_args(args, process)?),
            206 => SyscallEnter::IoSetup(IoSetup::from_args(args, process)?),
            207 => SyscallEnter::IoDestroy(IoDestroy::from_args(args, process)?),
            208 => SyscallEnter::IoGetevents(IoGetevents::from_args(args, process)?),
            209 => SyscallEnter::IoSubmit(IoSubmit::from_args(args, process)?),
            210 => SyscallEnter::IoCancel(IoCancel::from_args(args, process)?),
            211 => SyscallEnter::GetThreadArea(GetThreadArea::from_args(args, process)?),
            212 => SyscallEnter::LookupDcookie(LookupDcookie::from_args(args, process)?),
            213 => SyscallEnter::EpollCreate(EpollCreate::from_args(args, process)?),
            // 214 => SyscallEnter::EpollCtlOld(EpollCtlOld::from_args(args, process)?),
            // 215 => SyscallEnter::EpollWaitOld(EpollWaitOld::from_args(args, process)?),
            216 => SyscallEnter::RemapFilePages(RemapFilePages::from_args(args, process)?),
            217 => SyscallEnter::Getdents64(Getdents64::from_args(args, process)?),
            218 => SyscallEnter::SetTidAddress(SetTidAddress::from_args(args, process)?),
            219 => SyscallEnter::RestartSyscall(RestartSyscall::from_args(args, process)?),
            220 => SyscallEnter::Semtimedop(Semtimedop::from_args(args, process)?),
            221 => SyscallEnter::Fadvise64(Fadvise64::from_args(args, process)?),
            222 => SyscallEnter::TimerCreate(TimerCreate::from_args(args, process)?),
            223 => SyscallEnter::TimerSettime(TimerSettime::from_args(args, process)?),
            224 => SyscallEnter::TimerGettime(TimerGettime::from_args(args, process)?),
            225 => SyscallEnter::TimerGetoverrun(TimerGetoverrun::from_args(args, process)?),
            226 => SyscallEnter::TimerDelete(TimerDelete::from_args(args, process)?),
            227 => SyscallEnter::ClockSettime(ClockSettime::from_args(args, process)?),
            228 => SyscallEnter::ClockGettime(ClockGettime::from_args(args, process)?),
            229 => SyscallEnter::ClockGetres(ClockGetres::from_args(args, process)?),
            230 => SyscallEnter::ClockNanosleep(ClockNanosleep::from_args(args, process)?),
            231 => SyscallEnter::ExitGroup(ExitGroup::from_args(args, process)?),
            232 => SyscallEnter::EpollWait(EpollWait::from_args(args, process)?),
            233 => SyscallEnter::EpollCtl(EpollCtl::from_args(args, process)?),
            234 => SyscallEnter::Tgkill(Tgkill::from_args(args, process)?),
            235 => SyscallEnter::Utimes(Utimes::from_args(args, process)?),
            // 236 => SyscallEnter::Vserver(Vserver::from_args(args, process)?),
            237 => SyscallEnter::Mbind(Mbind::from_args(args, process)?),
            238 => SyscallEnter::SetMempolicy(SetMempolicy::from_args(args, process)?),
            239 => SyscallEnter::GetMempolicy(GetMempolicy::from_args(args, process)?),
            240 => SyscallEnter::MqOpen(MqOpen::from_args(args, process)?),
            241 => SyscallEnter::MqUnlink(MqUnlink::from_args(args, process)?),
            242 => SyscallEnter::MqTimedsend(MqTimedsend::from_args(args, process)?),
            243 => SyscallEnter::MqTimedreceive(MqTimedreceive::from_args(args, process)?),
            244 => SyscallEnter::MqNotify(MqNotify::from_args(args, process)?),
            245 => SyscallEnter::MqGetsetattr(MqGetsetattr::from_args(args, process)?),
            246 => SyscallEnter::KexecLoad(KexecLoad::from_args(args, process)?),
            247 => SyscallEnter::Waitid(Waitid::from_args(args, process)?),
            248 => SyscallEnter::AddKey(AddKey::from_args(args, process)?),
            249 => SyscallEnter::RequestKey(RequestKey::from_args(args, process)?),
            250 => SyscallEnter::Keyctl(Keyctl::from_args(args, process)?),
            251 => SyscallEnter::IoprioSet(IoprioSet::from_args(args, process)?),
            252 => SyscallEnter::IoprioGet(IoprioGet::from_args(args, process)?),
            253 => SyscallEnter::InotifyInit(InotifyInit::from_args(args, process)?),
            254 => SyscallEnter::InotifyAddWatch(InotifyAddWatch::from_args(args, process)?),
            255 => SyscallEnter::InotifyRmWatch(InotifyRmWatch::from_args(args, process)?),
            256 => SyscallEnter::MigratePages(MigratePages::from_args(args, process)?),
            257 => SyscallEnter::Openat(Openat::from_args(args, process)?),
            258 => SyscallEnter::Mkdirat(Mkdirat::from_args(args, process)?),
            259 => SyscallEnter::Mknodat(Mknodat::from_args(args, process)?),
            260 => SyscallEnter::Fchownat(Fchownat::from_args(args, process)?),
            261 => SyscallEnter::Futimesat(Futimesat::from_args(args, process)?),
            262 => SyscallEnter::Newfstatat(Newfstatat::from_args(args, process)?),
            263 => SyscallEnter::Unlinkat(Unlinkat::from_args(args, process)?),
            264 => SyscallEnter::Renameat(Renameat::from_args(args, process)?),
            265 => SyscallEnter::Linkat(Linkat::from_args(args, process)?),
            266 => SyscallEnter::Symlinkat(Symlinkat::from_args(args, process)?),
            267 => SyscallEnter::Readlinkat(Readlinkat::from_args(args, process)?),
            268 => SyscallEnter::Fchmodat(Fchmodat::from_args(args, process)?),
            269 => SyscallEnter::Faccessat(Faccessat::from_args(args, process)?),
            270 => SyscallEnter::Pselect6(Pselect6::from_args(args, process)?),
            271 => SyscallEnter::Ppoll(Ppoll::from_args(args, process)?),
            272 => SyscallEnter::Unshare(Unshare::from_args(args, process)?),
            273 => SyscallEnter::SetRobustList(SetRobustList::from_args(args, process)?),
            274 => SyscallEnter::GetRobustList(GetRobustList::from_args(args, process)?),
            275 => SyscallEnter::Splice(Splice::from_args(args, process)?),
            276 => SyscallEnter::Tee(Tee::from_args(args, process)?),
            277 => SyscallEnter::SyncFileRange(SyncFileRange::from_args(args, process)?),
            278 => SyscallEnter::Vmsplice(Vmsplice::from_args(args, process)?),
            279 => SyscallEnter::MovePages(MovePages::from_args(args, process)?),
            280 => SyscallEnter::Utimensat(Utimensat::from_args(args, process)?),
            281 => SyscallEnter::EpollPwait(EpollPwait::from_args(args, process)?),
            282 => SyscallEnter::Signalfd(Signalfd::from_args(args, process)?),
            283 => SyscallEnter::TimerfdCreate(TimerfdCreate::from_args(args, process)?),
            284 => SyscallEnter::Eventfd(Eventfd::from_args(args, process)?),
            285 => SyscallEnter::Fallocate(Fallocate::from_args(args, process)?),
            286 => SyscallEnter::TimerfdSettime(TimerfdSettime::from_args(args, process)?),
            287 => SyscallEnter::TimerfdGettime(TimerfdGettime::from_args(args, process)?),
            288 => SyscallEnter::Accept4(Accept4::from_args(args, process)?),
            289 => SyscallEnter::Signalfd4(Signalfd4::from_args(args, process)?),
            290 => SyscallEnter::Eventfd2(Eventfd2::from_args(args, process)?),
            291 => SyscallEnter::EpollCreate1(EpollCreate1::from_args(args, process)?),
            292 => SyscallEnter::Dup3(Dup3::from_args(args, process)?),
            293 => SyscallEnter::Pipe2(Pipe2::from_args(args, process)?),
            294 => SyscallEnter::InotifyInit1(InotifyInit1::from_args(args, process)?),
            295 => SyscallEnter::Preadv(Preadv::from_args(args, process)?),
            296 => SyscallEnter::Pwritev(Pwritev::from_args(args, process)?),
            297 => SyscallEnter::RtTgsigqueueinfo(RtTgsigqueueinfo::from_args(args, process)?),
            298 => SyscallEnter::PerfEventOpen(PerfEventOpen::from_args(args, process)?),
            299 => SyscallEnter::Recvmmsg(Recvmmsg::from_args(args, process)?),
            300 => SyscallEnter::FanotifyInit(FanotifyInit::from_args(args, process)?),
            301 => SyscallEnter::FanotifyMark(FanotifyMark::from_args(args, process)?),
            302 => SyscallEnter::Prlimit64(Prlimit64::from_args(args, process)?),
            303 => SyscallEnter::NameToHandleAt(NameToHandleAt::from_args(args, process)?),
            304 => SyscallEnter::OpenByHandleAt(OpenByHandleAt::from_args(args, process)?),
            305 => SyscallEnter::ClockAdjtime(ClockAdjtime::from_args(args, process)?),
            306 => SyscallEnter::Syncfs(Syncfs::from_args(args, process)?),
            307 => SyscallEnter::Sendmmsg(Sendmmsg::from_args(args, process)?),
            308 => SyscallEnter::Setns(Setns::from_args(args, process)?),
            309 => SyscallEnter::Getcpu(Getcpu::from_args(args, process)?),
            310 => SyscallEnter::ProcessVmReadv(ProcessVmReadv::from_args(args, process)?),
            311 => SyscallEnter::ProcessVmWritev(ProcessVmWritev::from_args(args, process)?),
            312 => SyscallEnter::Kcmp(Kcmp::from_args(args, process)?),
            313 => SyscallEnter::FinitModule(FinitModule::from_args(args, process)?),
            314 => SyscallEnter::SchedSetattr(SchedSetattr::from_args(args, process)?),
            315 => SyscallEnter::SchedGetattr(SchedGetattr::from_args(args, process)?),
            316 => SyscallEnter::Renameat2(Renameat2::from_args(args, process)?),
            317 => SyscallEnter::Seccomp(Seccomp::from_args(args, process)?),
            318 => SyscallEnter::Getrandom(Getrandom::from_args(args, process)?),
            319 => SyscallEnter::MemfdCreate(MemfdCreate::from_args(args, process)?),
            320 => SyscallEnter::KexecFileLoad(KexecFileLoad::from_args(args, process)?),
            321 => SyscallEnter::Bpf(Bpf::from_args(args, process)?),
            322 => SyscallEnter::Execveat(Execveat::from_args(args, process)?),
            323 => SyscallEnter::Userfaultfd(Userfaultfd::from_args(args, process)?),
            324 => SyscallEnter::Membarrier(Membarrier::from_args(args, process)?),
            325 => SyscallEnter::Mlock2(Mlock2::from_args(args, process)?),
            326 => SyscallEnter::CopyFileRange(CopyFileRange::from_args(args, process)?),
            327 => SyscallEnter::Preadv2(Preadv2::from_args(args, process)?),
            328 => SyscallEnter::Pwritev2(Pwritev2::from_args(args, process)?),
            329 => SyscallEnter::PkeyMprotect(PkeyMprotect::from_args(args, process)?),
            330 => SyscallEnter::PkeyAlloc(PkeyAlloc::from_args(args, process)?),
            331 => SyscallEnter::PkeyFree(PkeyFree::from_args(args, process)?),
            332 => SyscallEnter::Statx(Statx::from_args(args, process)?),
            333 => SyscallEnter::IoPgetevents(IoPgetevents::from_args(args, process)?),
            334 => SyscallEnter::Rseq(Rseq::from_args(args, process)?),
            424 => SyscallEnter::PidfdSendSignal(PidfdSendSignal::from_args(args, process)?),
            425 => SyscallEnter::IoUringSetup(IoUringSetup::from_args(args, process)?),
            426 => SyscallEnter::IoUringEnter(IoUringEnter::from_args(args, process)?),
            427 => SyscallEnter::IoUringRegister(IoUringRegister::from_args(args, process)?),
            428 => SyscallEnter::OpenTree(OpenTree::from_args(args, process)?),
            429 => SyscallEnter::MoveMount(MoveMount::from_args(args, process)?),
            430 => SyscallEnter::Fsopen(Fsopen::from_args(args, process)?),
            431 => SyscallEnter::Fsconfig(Fsconfig::from_args(args, process)?),
            432 => SyscallEnter::Fsmount(Fsmount::from_args(args, process)?),
            433 => SyscallEnter::Fspick(Fspick::from_args(args, process)?),
            434 => SyscallEnter::PidfdOpen(PidfdOpen::from_args(args, process)?),
            435 => SyscallEnter::Clone3(Clone3::from_args(args, process)?),
            437 => SyscallEnter::Openat2(Openat2::from_args(args, process)?),
            438 => SyscallEnter::PidfdGetfd(PidfdGetfd::from_args(args, process)?),
            512 => SyscallEnter::RtSigaction(RtSigaction::from_args(args, process)?),
            513 => SyscallEnter::RtSigreturn(RtSigreturn::from_args(args, process)?),
            514 => SyscallEnter::Ioctl(Ioctl::from_args(args, process)?),
            515 => SyscallEnter::Readv(Readv::from_args(args, process)?),
            516 => SyscallEnter::Writev(Writev::from_args(args, process)?),
            517 => SyscallEnter::Recvfrom(Recvfrom::from_args(args, process)?),
            518 => SyscallEnter::Sendmsg(Sendmsg::from_args(args, process)?),
            519 => SyscallEnter::Recvmsg(Recvmsg::from_args(args, process)?),
            520 => SyscallEnter::Execve(Execve::from_args(args, process)?),
            521 => SyscallEnter::Ptrace(Ptrace::from_args(args, process)?),
            522 => SyscallEnter::RtSigpending(RtSigpending::from_args(args, process)?),
            523 => SyscallEnter::RtSigtimedwait(RtSigtimedwait::from_args(args, process)?),
            524 => SyscallEnter::RtSigqueueinfo(RtSigqueueinfo::from_args(args, process)?),
            525 => SyscallEnter::Sigaltstack(Sigaltstack::from_args(args, process)?),
            526 => SyscallEnter::TimerCreate(TimerCreate::from_args(args, process)?),
            527 => SyscallEnter::MqNotify(MqNotify::from_args(args, process)?),
            528 => SyscallEnter::KexecLoad(KexecLoad::from_args(args, process)?),
            529 => SyscallEnter::Waitid(Waitid::from_args(args, process)?),
            530 => SyscallEnter::SetRobustList(SetRobustList::from_args(args, process)?),
            531 => SyscallEnter::GetRobustList(GetRobustList::from_args(args, process)?),
            532 => SyscallEnter::Vmsplice(Vmsplice::from_args(args, process)?),
            533 => SyscallEnter::MovePages(MovePages::from_args(args, process)?),
            534 => SyscallEnter::Preadv(Preadv::from_args(args, process)?),
            535 => SyscallEnter::Pwritev(Pwritev::from_args(args, process)?),
            536 => SyscallEnter::RtTgsigqueueinfo(RtTgsigqueueinfo::from_args(args, process)?),
            537 => SyscallEnter::Recvmmsg(Recvmmsg::from_args(args, process)?),
            538 => SyscallEnter::Sendmmsg(Sendmmsg::from_args(args, process)?),
            539 => SyscallEnter::ProcessVmReadv(ProcessVmReadv::from_args(args, process)?),
            540 => SyscallEnter::ProcessVmWritev(ProcessVmWritev::from_args(args, process)?),
            541 => SyscallEnter::Setsockopt(Setsockopt::from_args(args, process)?),
            542 => SyscallEnter::Getsockopt(Getsockopt::from_args(args, process)?),
            543 => SyscallEnter::IoSetup(IoSetup::from_args(args, process)?),
            544 => SyscallEnter::IoSubmit(IoSubmit::from_args(args, process)?),
            545 => SyscallEnter::Execveat(Execveat::from_args(args, process)?),
            546 => SyscallEnter::Preadv2(Preadv2::from_args(args, process)?),
            547 => SyscallEnter::Pwritev2(Pwritev2::from_args(args, process)?),
            x => {
                return Err(OsError::new(
                    ErrorKind::Other,
                    format!("Got unknown syscall enter {}", x),
                ))
            }
        };
        Ok(enter_call)
    }
}

impl SyscallExit {
    pub fn from_enter_event(
        enter: SyscallEnter,
        retval: i64,
        process: StoppedProcess,
    ) -> Result<Self, OsError> {
        if retval < 0 {
            return Ok(SyscallExit::SyscallError(OsError::from_raw_os_error(
                -retval as i32,
            )));
        }

        let exit_info = match enter {
            SyscallEnter::Accept(x) => {
                SyscallReturn::Accept(AcceptReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Accept4(x) => {
                SyscallReturn::Accept4(Accept4Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Access(x) => {
                SyscallReturn::Access(AccessReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Acct(x) => {
                SyscallReturn::Acct(AcctReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::AddKey(x) => {
                SyscallReturn::AddKey(AddKeyReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Adjtimex(x) => {
                SyscallReturn::Adjtimex(AdjtimexReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::AdjtimexTime32(x) => SyscallReturn::AdjtimexTime32(
                AdjtimexTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Alarm(x) => {
                SyscallReturn::Alarm(AlarmReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::AlphaPipe(x) => {
                SyscallReturn::AlphaPipe(AlphaPipeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::ArcGettls(x) => {
                SyscallReturn::ArcGettls(ArcGettlsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::ArcSettls(x) => {
                SyscallReturn::ArcSettls(ArcSettlsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::ArcUsrCmpxchg(x) => SyscallReturn::ArcUsrCmpxchg(
                ArcUsrCmpxchgReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Arch32Ftruncate64(x) => SyscallReturn::Arch32Ftruncate64(
                Arch32Ftruncate64Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Arch32Llseek(x) => SyscallReturn::Arch32Llseek(
                Arch32LlseekReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Arch32Personality(x) => SyscallReturn::Arch32Personality(
                Arch32PersonalityReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Arch32Pread(x) => {
                SyscallReturn::Arch32Pread(Arch32PreadReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Arch32Pwrite(x) => SyscallReturn::Arch32Pwrite(
                Arch32PwriteReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Arch32Sigaction(x) => SyscallReturn::Arch32Sigaction(
                Arch32SigactionReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Arch32Truncate64(x) => SyscallReturn::Arch32Truncate64(
                Arch32Truncate64Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Arch64Mremap(x) => SyscallReturn::Arch64Mremap(
                Arch64MremapReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Arch64Munmap(x) => SyscallReturn::Arch64Munmap(
                Arch64MunmapReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ArchPrctl(x) => {
                SyscallReturn::ArchPrctl(ArchPrctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Arm64Personality(x) => SyscallReturn::Arm64Personality(
                Arm64PersonalityReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Bdflush(x) => {
                SyscallReturn::Bdflush(BdflushReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Bind(x) => {
                SyscallReturn::Bind(BindReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Bpf(x) => {
                SyscallReturn::Bpf(BpfReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Brk(x) => {
                SyscallReturn::Brk(BrkReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Cachectl(x) => {
                SyscallReturn::Cachectl(CachectlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Cacheflush(x) => {
                SyscallReturn::Cacheflush(CacheflushReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Capget(x) => {
                SyscallReturn::Capget(CapgetReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Capset(x) => {
                SyscallReturn::Capset(CapsetReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Chdir(x) => {
                SyscallReturn::Chdir(ChdirReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Chmod(x) => {
                SyscallReturn::Chmod(ChmodReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Chown(x) => {
                SyscallReturn::Chown(ChownReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Chown16(x) => {
                SyscallReturn::Chown16(Chown16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Chroot(x) => {
                SyscallReturn::Chroot(ChrootReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::ClockAdjtime(x) => SyscallReturn::ClockAdjtime(
                ClockAdjtimeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ClockAdjtime32(x) => SyscallReturn::ClockAdjtime32(
                ClockAdjtime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ClockGetres(x) => {
                SyscallReturn::ClockGetres(ClockGetresReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::ClockGetresTime32(x) => SyscallReturn::ClockGetresTime32(
                ClockGetresTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ClockGettime(x) => SyscallReturn::ClockGettime(
                ClockGettimeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ClockGettime32(x) => SyscallReturn::ClockGettime32(
                ClockGettime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ClockNanosleep(x) => SyscallReturn::ClockNanosleep(
                ClockNanosleepReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ClockNanosleepTime32(x) => SyscallReturn::ClockNanosleepTime32(
                ClockNanosleepTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ClockSettime(x) => SyscallReturn::ClockSettime(
                ClockSettimeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ClockSettime32(x) => SyscallReturn::ClockSettime32(
                ClockSettime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Clone(x) => {
                SyscallReturn::Clone(CloneReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Clone3(x) => {
                SyscallReturn::Clone3(Clone3Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Close(x) => {
                SyscallReturn::Close(CloseReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Connect(x) => {
                SyscallReturn::Connect(ConnectReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::CopyFileRange(x) => SyscallReturn::CopyFileRange(
                CopyFileRangeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Creat(x) => {
                SyscallReturn::Creat(CreatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::CskyFadvise6464(x) => SyscallReturn::CskyFadvise6464(
                CskyFadvise6464Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::DebugSetcontext(x) => SyscallReturn::DebugSetcontext(
                DebugSetcontextReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::DeleteModule(x) => SyscallReturn::DeleteModule(
                DeleteModuleReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Dup(x) => {
                SyscallReturn::Dup(DupReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Dup2(x) => {
                SyscallReturn::Dup2(Dup2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Dup3(x) => {
                SyscallReturn::Dup3(Dup3Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::EpollCreate(x) => {
                SyscallReturn::EpollCreate(EpollCreateReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::EpollCreate1(x) => SyscallReturn::EpollCreate1(
                EpollCreate1Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::EpollCtl(x) => {
                SyscallReturn::EpollCtl(EpollCtlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::EpollPwait(x) => {
                SyscallReturn::EpollPwait(EpollPwaitReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::EpollWait(x) => {
                SyscallReturn::EpollWait(EpollWaitReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Eventfd(x) => {
                SyscallReturn::Eventfd(EventfdReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Eventfd2(x) => {
                SyscallReturn::Eventfd2(Eventfd2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Execve(x) => {
                SyscallReturn::Execve(ExecveReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Execveat(x) => {
                SyscallReturn::Execveat(ExecveatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Exit(x) => {
                SyscallReturn::Exit(ExitReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::ExitGroup(x) => {
                SyscallReturn::ExitGroup(ExitGroupReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Faccessat(x) => {
                SyscallReturn::Faccessat(FaccessatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fadvise64(x) => {
                SyscallReturn::Fadvise64(Fadvise64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fadvise6464(x) => {
                SyscallReturn::Fadvise6464(Fadvise6464Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fadvise6464Wrapper(x) => SyscallReturn::Fadvise6464Wrapper(
                Fadvise6464WrapperReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Fallocate(x) => {
                SyscallReturn::Fallocate(FallocateReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::FanotifyInit(x) => SyscallReturn::FanotifyInit(
                FanotifyInitReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::FanotifyMark(x) => SyscallReturn::FanotifyMark(
                FanotifyMarkReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Fchdir(x) => {
                SyscallReturn::Fchdir(FchdirReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fchmod(x) => {
                SyscallReturn::Fchmod(FchmodReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fchmodat(x) => {
                SyscallReturn::Fchmodat(FchmodatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fchown(x) => {
                SyscallReturn::Fchown(FchownReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fchown16(x) => {
                SyscallReturn::Fchown16(Fchown16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fchownat(x) => {
                SyscallReturn::Fchownat(FchownatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fcntl(x) => {
                SyscallReturn::Fcntl(FcntlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fcntl64(x) => {
                SyscallReturn::Fcntl64(Fcntl64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fdatasync(x) => {
                SyscallReturn::Fdatasync(FdatasyncReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fgetxattr(x) => {
                SyscallReturn::Fgetxattr(FgetxattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::FinitModule(x) => {
                SyscallReturn::FinitModule(FinitModuleReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Flistxattr(x) => {
                SyscallReturn::Flistxattr(FlistxattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Flock(x) => {
                SyscallReturn::Flock(FlockReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fork(x) => {
                SyscallReturn::Fork(ForkReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::FpUdfiexCrtl(x) => SyscallReturn::FpUdfiexCrtl(
                FpUdfiexCrtlReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Fremovexattr(x) => SyscallReturn::Fremovexattr(
                FremovexattrReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Fsconfig(x) => {
                SyscallReturn::Fsconfig(FsconfigReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fsetxattr(x) => {
                SyscallReturn::Fsetxattr(FsetxattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fsmount(x) => {
                SyscallReturn::Fsmount(FsmountReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fsopen(x) => {
                SyscallReturn::Fsopen(FsopenReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fspick(x) => {
                SyscallReturn::Fspick(FspickReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fstat(x) => {
                SyscallReturn::Fstat(FstatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fstat64(x) => {
                SyscallReturn::Fstat64(Fstat64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fstatat64(x) => {
                SyscallReturn::Fstatat64(Fstatat64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fstatfs(x) => {
                SyscallReturn::Fstatfs(FstatfsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fstatfs64(x) => {
                SyscallReturn::Fstatfs64(Fstatfs64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Fsync(x) => {
                SyscallReturn::Fsync(FsyncReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Ftruncate(x) => {
                SyscallReturn::Ftruncate(FtruncateReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Ftruncate64(x) => {
                SyscallReturn::Ftruncate64(Ftruncate64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Futex(x) => {
                SyscallReturn::Futex(FutexReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::FutexTime32(x) => {
                SyscallReturn::FutexTime32(FutexTime32Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Futimesat(x) => {
                SyscallReturn::Futimesat(FutimesatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::FutimesatTime32(x) => SyscallReturn::FutimesatTime32(
                FutimesatTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::GetMempolicy(x) => SyscallReturn::GetMempolicy(
                GetMempolicyReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::GetRobustList(x) => SyscallReturn::GetRobustList(
                GetRobustListReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::GetThreadArea(x) => SyscallReturn::GetThreadArea(
                GetThreadAreaReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Getcpu(x) => {
                SyscallReturn::Getcpu(GetcpuReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getcwd(x) => {
                SyscallReturn::Getcwd(GetcwdReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getdents(x) => {
                SyscallReturn::Getdents(GetdentsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getdents64(x) => {
                SyscallReturn::Getdents64(Getdents64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getdomainname(x) => SyscallReturn::Getdomainname(
                GetdomainnameReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Getdtablesize(x) => SyscallReturn::Getdtablesize(
                GetdtablesizeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Getegid(x) => {
                SyscallReturn::Getegid(GetegidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getegid16(x) => {
                SyscallReturn::Getegid16(Getegid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Geteuid(x) => {
                SyscallReturn::Geteuid(GeteuidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Geteuid16(x) => {
                SyscallReturn::Geteuid16(Geteuid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getgid(x) => {
                SyscallReturn::Getgid(GetgidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getgid16(x) => {
                SyscallReturn::Getgid16(Getgid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getgroups(x) => {
                SyscallReturn::Getgroups(GetgroupsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getgroups16(x) => {
                SyscallReturn::Getgroups16(Getgroups16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Gethostname(x) => {
                SyscallReturn::Gethostname(GethostnameReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getitimer(x) => {
                SyscallReturn::Getitimer(GetitimerReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getpagesize(x) => {
                SyscallReturn::Getpagesize(GetpagesizeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getpeername(x) => {
                SyscallReturn::Getpeername(GetpeernameReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getpgid(x) => {
                SyscallReturn::Getpgid(GetpgidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getpgrp(x) => {
                SyscallReturn::Getpgrp(GetpgrpReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getpid(x) => {
                SyscallReturn::Getpid(GetpidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getppid(x) => {
                SyscallReturn::Getppid(GetppidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getpriority(x) => {
                SyscallReturn::Getpriority(GetpriorityReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getrandom(x) => {
                SyscallReturn::Getrandom(GetrandomReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getresgid(x) => {
                SyscallReturn::Getresgid(GetresgidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getresgid16(x) => {
                SyscallReturn::Getresgid16(Getresgid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getresuid(x) => {
                SyscallReturn::Getresuid(GetresuidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getresuid16(x) => {
                SyscallReturn::Getresuid16(Getresuid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getrlimit(x) => {
                SyscallReturn::Getrlimit(GetrlimitReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getrusage(x) => {
                SyscallReturn::Getrusage(GetrusageReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getsid(x) => {
                SyscallReturn::Getsid(GetsidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getsockname(x) => {
                SyscallReturn::Getsockname(GetsocknameReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getsockopt(x) => {
                SyscallReturn::Getsockopt(GetsockoptReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Gettid(x) => {
                SyscallReturn::Gettid(GettidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Gettimeofday(x) => SyscallReturn::Gettimeofday(
                GettimeofdayReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Getuid(x) => {
                SyscallReturn::Getuid(GetuidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getuid16(x) => {
                SyscallReturn::Getuid16(Getuid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getxattr(x) => {
                SyscallReturn::Getxattr(GetxattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getxgid(x) => {
                SyscallReturn::Getxgid(GetxgidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getxpid(x) => {
                SyscallReturn::Getxpid(GetxpidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Getxuid(x) => {
                SyscallReturn::Getxuid(GetxuidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::InitModule(x) => {
                SyscallReturn::InitModule(InitModuleReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::InotifyAddWatch(x) => SyscallReturn::InotifyAddWatch(
                InotifyAddWatchReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::InotifyInit(x) => {
                SyscallReturn::InotifyInit(InotifyInitReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::InotifyInit1(x) => SyscallReturn::InotifyInit1(
                InotifyInit1Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::InotifyRmWatch(x) => SyscallReturn::InotifyRmWatch(
                InotifyRmWatchReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::IoCancel(x) => {
                SyscallReturn::IoCancel(IoCancelReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::IoDestroy(x) => {
                SyscallReturn::IoDestroy(IoDestroyReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::IoGetevents(x) => {
                SyscallReturn::IoGetevents(IoGeteventsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::IoGeteventsTime32(x) => SyscallReturn::IoGeteventsTime32(
                IoGeteventsTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::IoPgetevents(x) => SyscallReturn::IoPgetevents(
                IoPgeteventsReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::IoPgeteventsTime32(x) => SyscallReturn::IoPgeteventsTime32(
                IoPgeteventsTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::IoSetup(x) => {
                SyscallReturn::IoSetup(IoSetupReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::IoSubmit(x) => {
                SyscallReturn::IoSubmit(IoSubmitReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::IoUringEnter(x) => SyscallReturn::IoUringEnter(
                IoUringEnterReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::IoUringRegister(x) => SyscallReturn::IoUringRegister(
                IoUringRegisterReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::IoUringSetup(x) => SyscallReturn::IoUringSetup(
                IoUringSetupReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Ioctl(x) => {
                SyscallReturn::Ioctl(IoctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Ioperm(x) => {
                SyscallReturn::Ioperm(IopermReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Iopl(x) => {
                SyscallReturn::Iopl(IoplReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::IoprioGet(x) => {
                SyscallReturn::IoprioGet(IoprioGetReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::IoprioSet(x) => {
                SyscallReturn::IoprioSet(IoprioSetReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Ipc(x) => {
                SyscallReturn::Ipc(IpcReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Kcmp(x) => {
                SyscallReturn::Kcmp(KcmpReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::KernFeatures(x) => SyscallReturn::KernFeatures(
                KernFeaturesReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::KexecFileLoad(x) => SyscallReturn::KexecFileLoad(
                KexecFileLoadReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::KexecLoad(x) => {
                SyscallReturn::KexecLoad(KexecLoadReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Keyctl(x) => {
                SyscallReturn::Keyctl(KeyctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Kill(x) => {
                SyscallReturn::Kill(KillReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Lchown(x) => {
                SyscallReturn::Lchown(LchownReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Lchown16(x) => {
                SyscallReturn::Lchown16(Lchown16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Lgetxattr(x) => {
                SyscallReturn::Lgetxattr(LgetxattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Link(x) => {
                SyscallReturn::Link(LinkReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Linkat(x) => {
                SyscallReturn::Linkat(LinkatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Listen(x) => {
                SyscallReturn::Listen(ListenReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Listxattr(x) => {
                SyscallReturn::Listxattr(ListxattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Llistxattr(x) => {
                SyscallReturn::Llistxattr(LlistxattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Llseek(x) => {
                SyscallReturn::Llseek(LlseekReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::LookupDcookie(x) => SyscallReturn::LookupDcookie(
                LookupDcookieReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Lremovexattr(x) => SyscallReturn::Lremovexattr(
                LremovexattrReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Lseek(x) => {
                SyscallReturn::Lseek(LseekReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Lsetxattr(x) => {
                SyscallReturn::Lsetxattr(LsetxattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Lstat(x) => {
                SyscallReturn::Lstat(LstatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Lstat64(x) => {
                SyscallReturn::Lstat64(Lstat64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Madvise(x) => {
                SyscallReturn::Madvise(MadviseReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mbind(x) => {
                SyscallReturn::Mbind(MbindReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Membarrier(x) => {
                SyscallReturn::Membarrier(MembarrierReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MemfdCreate(x) => {
                SyscallReturn::MemfdCreate(MemfdCreateReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MemoryOrdering(x) => SyscallReturn::MemoryOrdering(
                MemoryOrderingReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::MigratePages(x) => SyscallReturn::MigratePages(
                MigratePagesReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Mincore(x) => {
                SyscallReturn::Mincore(MincoreReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MipsMmap(x) => {
                SyscallReturn::MipsMmap(MipsMmapReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MipsMmap2(x) => {
                SyscallReturn::MipsMmap2(MipsMmap2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mkdir(x) => {
                SyscallReturn::Mkdir(MkdirReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mkdirat(x) => {
                SyscallReturn::Mkdirat(MkdiratReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mknod(x) => {
                SyscallReturn::Mknod(MknodReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mknodat(x) => {
                SyscallReturn::Mknodat(MknodatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mlock(x) => {
                SyscallReturn::Mlock(MlockReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mlock2(x) => {
                SyscallReturn::Mlock2(Mlock2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mlockall(x) => {
                SyscallReturn::Mlockall(MlockallReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mmap(x) => {
                SyscallReturn::Mmap(MmapReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mmap2(x) => {
                SyscallReturn::Mmap2(Mmap2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MmapPgoff(x) => {
                SyscallReturn::MmapPgoff(MmapPgoffReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::ModifyLdt(x) => {
                SyscallReturn::ModifyLdt(ModifyLdtReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mount(x) => {
                SyscallReturn::Mount(MountReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MoveMount(x) => {
                SyscallReturn::MoveMount(MoveMountReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MovePages(x) => {
                SyscallReturn::MovePages(MovePagesReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mprotect(x) => {
                SyscallReturn::Mprotect(MprotectReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MqGetsetattr(x) => SyscallReturn::MqGetsetattr(
                MqGetsetattrReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::MqNotify(x) => {
                SyscallReturn::MqNotify(MqNotifyReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MqOpen(x) => {
                SyscallReturn::MqOpen(MqOpenReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MqTimedreceive(x) => SyscallReturn::MqTimedreceive(
                MqTimedreceiveReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::MqTimedreceiveTime32(x) => SyscallReturn::MqTimedreceiveTime32(
                MqTimedreceiveTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::MqTimedsend(x) => {
                SyscallReturn::MqTimedsend(MqTimedsendReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::MqTimedsendTime32(x) => SyscallReturn::MqTimedsendTime32(
                MqTimedsendTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::MqUnlink(x) => {
                SyscallReturn::MqUnlink(MqUnlinkReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Mremap(x) => {
                SyscallReturn::Mremap(MremapReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Msgctl(x) => {
                SyscallReturn::Msgctl(MsgctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Msgget(x) => {
                SyscallReturn::Msgget(MsggetReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Msgrcv(x) => {
                SyscallReturn::Msgrcv(MsgrcvReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Msgsnd(x) => {
                SyscallReturn::Msgsnd(MsgsndReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Msync(x) => {
                SyscallReturn::Msync(MsyncReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Munlock(x) => {
                SyscallReturn::Munlock(MunlockReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Munlockall(x) => {
                SyscallReturn::Munlockall(MunlockallReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Munmap(x) => {
                SyscallReturn::Munmap(MunmapReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::NameToHandleAt(x) => SyscallReturn::NameToHandleAt(
                NameToHandleAtReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Nanosleep(x) => {
                SyscallReturn::Nanosleep(NanosleepReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::NanosleepTime32(x) => SyscallReturn::NanosleepTime32(
                NanosleepTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Newfstat(x) => {
                SyscallReturn::Newfstat(NewfstatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Newfstatat(x) => {
                SyscallReturn::Newfstatat(NewfstatatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Newlstat(x) => {
                SyscallReturn::Newlstat(NewlstatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Newstat(x) => {
                SyscallReturn::Newstat(NewstatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Newuname(x) => {
                SyscallReturn::Newuname(NewunameReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::NiSyscall(x) => {
                SyscallReturn::NiSyscall(NiSyscallReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Nice(x) => {
                SyscallReturn::Nice(NiceReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::NisSyscall(x) => {
                SyscallReturn::NisSyscall(NisSyscallReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OldAdjtimex(x) => {
                SyscallReturn::OldAdjtimex(OldAdjtimexReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OldGetrlimit(x) => SyscallReturn::OldGetrlimit(
                OldGetrlimitReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OldMmap(x) => {
                SyscallReturn::OldMmap(OldMmapReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OldMsgctl(x) => {
                SyscallReturn::OldMsgctl(OldMsgctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OldReaddir(x) => {
                SyscallReturn::OldReaddir(OldReaddirReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OldSelect(x) => {
                SyscallReturn::OldSelect(OldSelectReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OldSemctl(x) => {
                SyscallReturn::OldSemctl(OldSemctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OldShmctl(x) => {
                SyscallReturn::OldShmctl(OldShmctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Oldumount(x) => {
                SyscallReturn::Oldumount(OldumountReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Olduname(x) => {
                SyscallReturn::Olduname(OldunameReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Open(x) => {
                SyscallReturn::Open(OpenReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OpenByHandleAt(x) => SyscallReturn::OpenByHandleAt(
                OpenByHandleAtReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OpenTree(x) => {
                SyscallReturn::OpenTree(OpenTreeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Openat(x) => {
                SyscallReturn::Openat(OpenatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Openat2(x) => {
                SyscallReturn::Openat2(Openat2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfBrk(x) => {
                SyscallReturn::OsfBrk(OsfBrkReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfFstat(x) => {
                SyscallReturn::OsfFstat(OsfFstatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfFstatfs(x) => {
                SyscallReturn::OsfFstatfs(OsfFstatfsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfFstatfs64(x) => SyscallReturn::OsfFstatfs64(
                OsfFstatfs64Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfGetdirentries(x) => SyscallReturn::OsfGetdirentries(
                OsfGetdirentriesReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfGetdomainname(x) => SyscallReturn::OsfGetdomainname(
                OsfGetdomainnameReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfGetpriority(x) => SyscallReturn::OsfGetpriority(
                OsfGetpriorityReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfGetrusage(x) => SyscallReturn::OsfGetrusage(
                OsfGetrusageReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfGetsysinfo(x) => SyscallReturn::OsfGetsysinfo(
                OsfGetsysinfoReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfGettimeofday(x) => SyscallReturn::OsfGettimeofday(
                OsfGettimeofdayReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfLstat(x) => {
                SyscallReturn::OsfLstat(OsfLstatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfMmap(x) => {
                SyscallReturn::OsfMmap(OsfMmapReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfMount(x) => {
                SyscallReturn::OsfMount(OsfMountReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfProplistSyscall(x) => SyscallReturn::OsfProplistSyscall(
                OsfProplistSyscallReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfReadv(x) => {
                SyscallReturn::OsfReadv(OsfReadvReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfSelect(x) => {
                SyscallReturn::OsfSelect(OsfSelectReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfSetProgramAttributes(x) => SyscallReturn::OsfSetProgramAttributes(
                OsfSetProgramAttributesReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfSetsysinfo(x) => SyscallReturn::OsfSetsysinfo(
                OsfSetsysinfoReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfSettimeofday(x) => SyscallReturn::OsfSettimeofday(
                OsfSettimeofdayReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfSigaction(x) => SyscallReturn::OsfSigaction(
                OsfSigactionReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfSigprocmask(x) => SyscallReturn::OsfSigprocmask(
                OsfSigprocmaskReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfSigstack(x) => {
                SyscallReturn::OsfSigstack(OsfSigstackReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfStat(x) => {
                SyscallReturn::OsfStat(OsfStatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfStatfs(x) => {
                SyscallReturn::OsfStatfs(OsfStatfsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfStatfs64(x) => {
                SyscallReturn::OsfStatfs64(OsfStatfs64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfSysinfo(x) => {
                SyscallReturn::OsfSysinfo(OsfSysinfoReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfUsleepThread(x) => SyscallReturn::OsfUsleepThread(
                OsfUsleepThreadReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::OsfUtimes(x) => {
                SyscallReturn::OsfUtimes(OsfUtimesReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfUtsname(x) => {
                SyscallReturn::OsfUtsname(OsfUtsnameReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfWait4(x) => {
                SyscallReturn::OsfWait4(OsfWait4Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::OsfWritev(x) => {
                SyscallReturn::OsfWritev(OsfWritevReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Pause(x) => {
                SyscallReturn::Pause(PauseReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::PciconfigIobase(x) => SyscallReturn::PciconfigIobase(
                PciconfigIobaseReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::PciconfigRead(x) => SyscallReturn::PciconfigRead(
                PciconfigReadReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::PciconfigWrite(x) => SyscallReturn::PciconfigWrite(
                PciconfigWriteReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::PerfEventOpen(x) => SyscallReturn::PerfEventOpen(
                PerfEventOpenReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Personality(x) => {
                SyscallReturn::Personality(PersonalityReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::PidfdGetfd(x) => {
                SyscallReturn::PidfdGetfd(PidfdGetfdReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::PidfdOpen(x) => {
                SyscallReturn::PidfdOpen(PidfdOpenReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::PidfdSendSignal(x) => SyscallReturn::PidfdSendSignal(
                PidfdSendSignalReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Pipe(x) => {
                SyscallReturn::Pipe(PipeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Pipe2(x) => {
                SyscallReturn::Pipe2(Pipe2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::PivotRoot(x) => {
                SyscallReturn::PivotRoot(PivotRootReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::PkeyAlloc(x) => {
                SyscallReturn::PkeyAlloc(PkeyAllocReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::PkeyFree(x) => {
                SyscallReturn::PkeyFree(PkeyFreeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::PkeyMprotect(x) => SyscallReturn::PkeyMprotect(
                PkeyMprotectReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Poll(x) => {
                SyscallReturn::Poll(PollReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Ppoll(x) => {
                SyscallReturn::Ppoll(PpollReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::PpollTime32(x) => {
                SyscallReturn::PpollTime32(PpollTime32Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Prctl(x) => {
                SyscallReturn::Prctl(PrctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Pread64(x) => {
                SyscallReturn::Pread64(Pread64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Preadv(x) => {
                SyscallReturn::Preadv(PreadvReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Preadv2(x) => {
                SyscallReturn::Preadv2(Preadv2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Prlimit64(x) => {
                SyscallReturn::Prlimit64(Prlimit64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::ProcessVmReadv(x) => SyscallReturn::ProcessVmReadv(
                ProcessVmReadvReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::ProcessVmWritev(x) => SyscallReturn::ProcessVmWritev(
                ProcessVmWritevReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Pselect6(x) => {
                SyscallReturn::Pselect6(Pselect6Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Pselect6Time32(x) => SyscallReturn::Pselect6Time32(
                Pselect6Time32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Ptrace(x) => {
                SyscallReturn::Ptrace(PtraceReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Pwrite64(x) => {
                SyscallReturn::Pwrite64(Pwrite64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Pwritev(x) => {
                SyscallReturn::Pwritev(PwritevReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Pwritev2(x) => {
                SyscallReturn::Pwritev2(Pwritev2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Quotactl(x) => {
                SyscallReturn::Quotactl(QuotactlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Read(x) => {
                SyscallReturn::Read(ReadReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Readahead(x) => {
                SyscallReturn::Readahead(ReadaheadReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Readlink(x) => {
                SyscallReturn::Readlink(ReadlinkReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Readlinkat(x) => {
                SyscallReturn::Readlinkat(ReadlinkatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Readv(x) => {
                SyscallReturn::Readv(ReadvReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Reboot(x) => {
                SyscallReturn::Reboot(RebootReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Recv(x) => {
                SyscallReturn::Recv(RecvReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Recvfrom(x) => {
                SyscallReturn::Recvfrom(RecvfromReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Recvmmsg(x) => {
                SyscallReturn::Recvmmsg(RecvmmsgReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::RecvmmsgTime32(x) => SyscallReturn::RecvmmsgTime32(
                RecvmmsgTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Recvmsg(x) => {
                SyscallReturn::Recvmsg(RecvmsgReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::RemapFilePages(x) => SyscallReturn::RemapFilePages(
                RemapFilePagesReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Removexattr(x) => {
                SyscallReturn::Removexattr(RemovexattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Rename(x) => {
                SyscallReturn::Rename(RenameReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Renameat(x) => {
                SyscallReturn::Renameat(RenameatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Renameat2(x) => {
                SyscallReturn::Renameat2(Renameat2Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::RequestKey(x) => {
                SyscallReturn::RequestKey(RequestKeyReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::RestartSyscall(x) => SyscallReturn::RestartSyscall(
                RestartSyscallReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::RiscvFlushIcache(x) => SyscallReturn::RiscvFlushIcache(
                RiscvFlushIcacheReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Rmdir(x) => {
                SyscallReturn::Rmdir(RmdirReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Rseq(x) => {
                SyscallReturn::Rseq(RseqReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::RtSigaction(x) => {
                SyscallReturn::RtSigaction(RtSigactionReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::RtSigpending(x) => SyscallReturn::RtSigpending(
                RtSigpendingReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::RtSigprocmask(x) => SyscallReturn::RtSigprocmask(
                RtSigprocmaskReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::RtSigqueueinfo(x) => SyscallReturn::RtSigqueueinfo(
                RtSigqueueinfoReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::RtSigreturn(x) => {
                SyscallReturn::RtSigreturn(RtSigreturnReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::RtSigsuspend(x) => SyscallReturn::RtSigsuspend(
                RtSigsuspendReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::RtSigtimedwait(x) => SyscallReturn::RtSigtimedwait(
                RtSigtimedwaitReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::RtSigtimedwaitTime32(x) => SyscallReturn::RtSigtimedwaitTime32(
                RtSigtimedwaitTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::RtTgsigqueueinfo(x) => SyscallReturn::RtTgsigqueueinfo(
                RtTgsigqueueinfoReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Rtas(x) => {
                SyscallReturn::Rtas(RtasReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::S390GuardedStorage(x) => SyscallReturn::S390GuardedStorage(
                S390GuardedStorageReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::S390Ipc(x) => {
                SyscallReturn::S390Ipc(S390IpcReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::S390PciMmioRead(x) => SyscallReturn::S390PciMmioRead(
                S390PciMmioReadReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::S390PciMmioWrite(x) => SyscallReturn::S390PciMmioWrite(
                S390PciMmioWriteReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::S390Personality(x) => SyscallReturn::S390Personality(
                S390PersonalityReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::S390RuntimeInstr(x) => SyscallReturn::S390RuntimeInstr(
                S390RuntimeInstrReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::S390Sthyi(x) => {
                SyscallReturn::S390Sthyi(S390SthyiReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SchedGetPriorityMax(x) => SyscallReturn::SchedGetPriorityMax(
                SchedGetPriorityMaxReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedGetPriorityMin(x) => SyscallReturn::SchedGetPriorityMin(
                SchedGetPriorityMinReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedGetaffinity(x) => SyscallReturn::SchedGetaffinity(
                SchedGetaffinityReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedGetattr(x) => SyscallReturn::SchedGetattr(
                SchedGetattrReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedGetparam(x) => SyscallReturn::SchedGetparam(
                SchedGetparamReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedGetscheduler(x) => SyscallReturn::SchedGetscheduler(
                SchedGetschedulerReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedRrGetInterval(x) => SyscallReturn::SchedRrGetInterval(
                SchedRrGetIntervalReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedRrGetIntervalTime32(x) => SyscallReturn::SchedRrGetIntervalTime32(
                SchedRrGetIntervalTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedSetaffinity(x) => SyscallReturn::SchedSetaffinity(
                SchedSetaffinityReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedSetattr(x) => SyscallReturn::SchedSetattr(
                SchedSetattrReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedSetparam(x) => SyscallReturn::SchedSetparam(
                SchedSetparamReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedSetscheduler(x) => SyscallReturn::SchedSetscheduler(
                SchedSetschedulerReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SchedYield(x) => {
                SyscallReturn::SchedYield(SchedYieldReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Seccomp(x) => {
                SyscallReturn::Seccomp(SeccompReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Select(x) => {
                SyscallReturn::Select(SelectReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Semctl(x) => {
                SyscallReturn::Semctl(SemctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Semget(x) => {
                SyscallReturn::Semget(SemgetReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Semop(x) => {
                SyscallReturn::Semop(SemopReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Semtimedop(x) => {
                SyscallReturn::Semtimedop(SemtimedopReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SemtimedopTime32(x) => SyscallReturn::SemtimedopTime32(
                SemtimedopTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Send(x) => {
                SyscallReturn::Send(SendReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sendfile(x) => {
                SyscallReturn::Sendfile(SendfileReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sendfile64(x) => {
                SyscallReturn::Sendfile64(Sendfile64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sendmmsg(x) => {
                SyscallReturn::Sendmmsg(SendmmsgReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sendmsg(x) => {
                SyscallReturn::Sendmsg(SendmsgReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sendto(x) => {
                SyscallReturn::Sendto(SendtoReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SetMempolicy(x) => SyscallReturn::SetMempolicy(
                SetMempolicyReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SetRobustList(x) => SyscallReturn::SetRobustList(
                SetRobustListReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SetThreadArea(x) => SyscallReturn::SetThreadArea(
                SetThreadAreaReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SetTidAddress(x) => SyscallReturn::SetTidAddress(
                SetTidAddressReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Setdomainname(x) => SyscallReturn::Setdomainname(
                SetdomainnameReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Setfsgid(x) => {
                SyscallReturn::Setfsgid(SetfsgidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setfsgid16(x) => {
                SyscallReturn::Setfsgid16(Setfsgid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setfsuid(x) => {
                SyscallReturn::Setfsuid(SetfsuidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setfsuid16(x) => {
                SyscallReturn::Setfsuid16(Setfsuid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setgid(x) => {
                SyscallReturn::Setgid(SetgidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setgid16(x) => {
                SyscallReturn::Setgid16(Setgid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setgroups(x) => {
                SyscallReturn::Setgroups(SetgroupsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setgroups16(x) => {
                SyscallReturn::Setgroups16(Setgroups16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sethae(x) => {
                SyscallReturn::Sethae(SethaeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sethostname(x) => {
                SyscallReturn::Sethostname(SethostnameReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setitimer(x) => {
                SyscallReturn::Setitimer(SetitimerReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setns(x) => {
                SyscallReturn::Setns(SetnsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setpgid(x) => {
                SyscallReturn::Setpgid(SetpgidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setpriority(x) => {
                SyscallReturn::Setpriority(SetpriorityReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setregid(x) => {
                SyscallReturn::Setregid(SetregidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setregid16(x) => {
                SyscallReturn::Setregid16(Setregid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setresgid(x) => {
                SyscallReturn::Setresgid(SetresgidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setresgid16(x) => {
                SyscallReturn::Setresgid16(Setresgid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setresuid(x) => {
                SyscallReturn::Setresuid(SetresuidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setresuid16(x) => {
                SyscallReturn::Setresuid16(Setresuid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setreuid(x) => {
                SyscallReturn::Setreuid(SetreuidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setreuid16(x) => {
                SyscallReturn::Setreuid16(Setreuid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setrlimit(x) => {
                SyscallReturn::Setrlimit(SetrlimitReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setsid(x) => {
                SyscallReturn::Setsid(SetsidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setsockopt(x) => {
                SyscallReturn::Setsockopt(SetsockoptReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Settimeofday(x) => SyscallReturn::Settimeofday(
                SettimeofdayReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Setuid(x) => {
                SyscallReturn::Setuid(SetuidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setuid16(x) => {
                SyscallReturn::Setuid16(Setuid16Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Setxattr(x) => {
                SyscallReturn::Setxattr(SetxattrReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sgetmask(x) => {
                SyscallReturn::Sgetmask(SgetmaskReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Shmat(x) => {
                SyscallReturn::Shmat(ShmatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Shmctl(x) => {
                SyscallReturn::Shmctl(ShmctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Shmdt(x) => {
                SyscallReturn::Shmdt(ShmdtReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Shmget(x) => {
                SyscallReturn::Shmget(ShmgetReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Shutdown(x) => {
                SyscallReturn::Shutdown(ShutdownReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sigaction(x) => {
                SyscallReturn::Sigaction(SigactionReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sigaltstack(x) => {
                SyscallReturn::Sigaltstack(SigaltstackReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Signal(x) => {
                SyscallReturn::Signal(SignalReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Signalfd(x) => {
                SyscallReturn::Signalfd(SignalfdReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Signalfd4(x) => {
                SyscallReturn::Signalfd4(Signalfd4Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sigpending(x) => {
                SyscallReturn::Sigpending(SigpendingReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sigprocmask(x) => {
                SyscallReturn::Sigprocmask(SigprocmaskReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sigreturn(x) => {
                SyscallReturn::Sigreturn(SigreturnReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sigsuspend(x) => {
                SyscallReturn::Sigsuspend(SigsuspendReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Socket(x) => {
                SyscallReturn::Socket(SocketReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Socketcall(x) => {
                SyscallReturn::Socketcall(SocketcallReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Socketpair(x) => {
                SyscallReturn::Socketpair(SocketpairReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sparc64Personality(x) => SyscallReturn::Sparc64Personality(
                Sparc64PersonalityReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SparcAdjtimex(x) => SyscallReturn::SparcAdjtimex(
                SparcAdjtimexReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SparcClockAdjtime(x) => SyscallReturn::SparcClockAdjtime(
                SparcClockAdjtimeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SparcIpc(x) => {
                SyscallReturn::SparcIpc(SparcIpcReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SparcPipe(x) => {
                SyscallReturn::SparcPipe(SparcPipeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SparcRemapFilePages(x) => SyscallReturn::SparcRemapFilePages(
                SparcRemapFilePagesReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SparcSigaction(x) => SyscallReturn::SparcSigaction(
                SparcSigactionReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Splice(x) => {
                SyscallReturn::Splice(SpliceReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SpuCreate(x) => {
                SyscallReturn::SpuCreate(SpuCreateReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SpuRun(x) => {
                SyscallReturn::SpuRun(SpuRunReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Ssetmask(x) => {
                SyscallReturn::Ssetmask(SsetmaskReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Stat(x) => {
                SyscallReturn::Stat(StatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Stat64(x) => {
                SyscallReturn::Stat64(Stat64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Statfs(x) => {
                SyscallReturn::Statfs(StatfsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Statfs64(x) => {
                SyscallReturn::Statfs64(Statfs64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Statx(x) => {
                SyscallReturn::Statx(StatxReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Stime(x) => {
                SyscallReturn::Stime(StimeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Stime32(x) => {
                SyscallReturn::Stime32(Stime32Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SubpageProt(x) => {
                SyscallReturn::SubpageProt(SubpageProtReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Swapcontext(x) => {
                SyscallReturn::Swapcontext(SwapcontextReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Swapoff(x) => {
                SyscallReturn::Swapoff(SwapoffReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Swapon(x) => {
                SyscallReturn::Swapon(SwaponReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SwitchEndian(x) => SyscallReturn::SwitchEndian(
                SwitchEndianReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Symlink(x) => {
                SyscallReturn::Symlink(SymlinkReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Symlinkat(x) => {
                SyscallReturn::Symlinkat(SymlinkatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sync(x) => {
                SyscallReturn::Sync(SyncReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::SyncFileRange(x) => SyscallReturn::SyncFileRange(
                SyncFileRangeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::SyncFileRange2(x) => SyscallReturn::SyncFileRange2(
                SyncFileRange2Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Syncfs(x) => {
                SyscallReturn::Syncfs(SyncfsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sysctl(x) => {
                SyscallReturn::Sysctl(SysctlReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sysfs(x) => {
                SyscallReturn::Sysfs(SysfsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sysinfo(x) => {
                SyscallReturn::Sysinfo(SysinfoReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Syslog(x) => {
                SyscallReturn::Syslog(SyslogReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Sysmips(x) => {
                SyscallReturn::Sysmips(SysmipsReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Tee(x) => {
                SyscallReturn::Tee(TeeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Tgkill(x) => {
                SyscallReturn::Tgkill(TgkillReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Time(x) => {
                SyscallReturn::Time(TimeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Time32(x) => {
                SyscallReturn::Time32(Time32Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::TimerCreate(x) => {
                SyscallReturn::TimerCreate(TimerCreateReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::TimerDelete(x) => {
                SyscallReturn::TimerDelete(TimerDeleteReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::TimerGetoverrun(x) => SyscallReturn::TimerGetoverrun(
                TimerGetoverrunReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::TimerGettime(x) => SyscallReturn::TimerGettime(
                TimerGettimeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::TimerGettime32(x) => SyscallReturn::TimerGettime32(
                TimerGettime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::TimerSettime(x) => SyscallReturn::TimerSettime(
                TimerSettimeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::TimerSettime32(x) => SyscallReturn::TimerSettime32(
                TimerSettime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::TimerfdCreate(x) => SyscallReturn::TimerfdCreate(
                TimerfdCreateReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::TimerfdGettime(x) => SyscallReturn::TimerfdGettime(
                TimerfdGettimeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::TimerfdGettime32(x) => SyscallReturn::TimerfdGettime32(
                TimerfdGettime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::TimerfdSettime(x) => SyscallReturn::TimerfdSettime(
                TimerfdSettimeReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::TimerfdSettime32(x) => SyscallReturn::TimerfdSettime32(
                TimerfdSettime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Times(x) => {
                SyscallReturn::Times(TimesReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Tkill(x) => {
                SyscallReturn::Tkill(TkillReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Truncate(x) => {
                SyscallReturn::Truncate(TruncateReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Truncate64(x) => {
                SyscallReturn::Truncate64(Truncate64Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Umask(x) => {
                SyscallReturn::Umask(UmaskReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Umount(x) => {
                SyscallReturn::Umount(UmountReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Uname(x) => {
                SyscallReturn::Uname(UnameReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Unlink(x) => {
                SyscallReturn::Unlink(UnlinkReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Unlinkat(x) => {
                SyscallReturn::Unlinkat(UnlinkatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Unshare(x) => {
                SyscallReturn::Unshare(UnshareReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Uselib(x) => {
                SyscallReturn::Uselib(UselibReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Userfaultfd(x) => {
                SyscallReturn::Userfaultfd(UserfaultfdReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Ustat(x) => {
                SyscallReturn::Ustat(UstatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Utime(x) => {
                SyscallReturn::Utime(UtimeReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Utime32(x) => {
                SyscallReturn::Utime32(Utime32Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Utimensat(x) => {
                SyscallReturn::Utimensat(UtimensatReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::UtimensatTime32(x) => SyscallReturn::UtimensatTime32(
                UtimensatTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Utimes(x) => {
                SyscallReturn::Utimes(UtimesReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::UtimesTime32(x) => SyscallReturn::UtimesTime32(
                UtimesTime32Return::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::UtrapInstall(x) => SyscallReturn::UtrapInstall(
                UtrapInstallReturn::from_enter_event(x, retval, process)?,
            ),
            SyscallEnter::Vfork(x) => {
                SyscallReturn::Vfork(VforkReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Vhangup(x) => {
                SyscallReturn::Vhangup(VhangupReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Vm86(x) => {
                SyscallReturn::Vm86(Vm86Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Vm86old(x) => {
                SyscallReturn::Vm86old(Vm86oldReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Vmsplice(x) => {
                SyscallReturn::Vmsplice(VmspliceReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Wait4(x) => {
                SyscallReturn::Wait4(Wait4Return::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Waitid(x) => {
                SyscallReturn::Waitid(WaitidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Waitpid(x) => {
                SyscallReturn::Waitpid(WaitpidReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Write(x) => {
                SyscallReturn::Write(WriteReturn::from_enter_event(x, retval, process)?)
            }
            SyscallEnter::Writev(x) => {
                SyscallReturn::Writev(WritevReturn::from_enter_event(x, retval, process)?)
            }
        };
        Ok(SyscallExit::SyscallGood(exit_info))
    }
}
