#![allow(unused_variables)]

use bitflags::_core::ffi::c_void;

use crate::OsError;
use crate::StoppedProcess;

use super::syscall_args::*;
use super::syscall_defs_enter::*;

#[derive(Debug, Clone)]
pub struct AcceptReturn {}

#[derive(Debug, Clone)]
pub struct Accept4Return {}

#[derive(Debug, Clone)]
pub struct AccessReturn {}

#[derive(Debug, Clone)]
pub struct AcctReturn {}

#[derive(Debug, Clone)]
pub struct AddKeyReturn {}

#[derive(Debug, Clone)]
pub struct AdjtimexReturn {}

#[derive(Debug, Clone)]
pub struct AdjtimexTime32Return {}

#[derive(Debug, Clone)]
pub struct AlarmReturn {}

#[derive(Debug, Clone)]
pub struct AlphaPipeReturn {}

#[derive(Debug, Clone)]
pub struct ArcGettlsReturn {}

#[derive(Debug, Clone)]
pub struct ArcSettlsReturn {}

#[derive(Debug, Clone)]
pub struct ArcUsrCmpxchgReturn {}

#[derive(Debug, Clone)]
pub struct Arch32Ftruncate64Return {}

#[derive(Debug, Clone)]
pub struct Arch32LlseekReturn {}

#[derive(Debug, Clone)]
pub struct Arch32PersonalityReturn {}

#[derive(Debug, Clone)]
pub struct Arch32PreadReturn {}

#[derive(Debug, Clone)]
pub struct Arch32PwriteReturn {}

#[derive(Debug, Clone)]
pub struct Arch32SigactionReturn {}

#[derive(Debug, Clone)]
pub struct Arch32Truncate64Return {}

#[derive(Debug, Clone)]
pub struct Arch64MremapReturn {}

#[derive(Debug, Clone)]
pub struct Arch64MunmapReturn {}

#[derive(Debug, Clone)]
pub struct ArchPrctlReturn {}

#[derive(Debug, Clone)]
pub struct Arm64PersonalityReturn {}

#[derive(Debug, Clone)]
pub struct BdflushReturn {}

#[derive(Debug, Clone)]
pub struct BindReturn {}

#[derive(Debug, Clone)]
pub struct BpfReturn {}

#[derive(Debug, Clone)]
pub struct BrkReturn {}

#[derive(Debug, Clone)]
pub struct CachectlReturn {}

#[derive(Debug, Clone)]
pub struct CacheflushReturn {}

#[derive(Debug, Clone)]
pub struct CapgetReturn {}

#[derive(Debug, Clone)]
pub struct CapsetReturn {}

#[derive(Debug, Clone)]
pub struct ChdirReturn {}

#[derive(Debug, Clone)]
pub struct ChmodReturn {}

#[derive(Debug, Clone)]
pub struct ChownReturn {}

#[derive(Debug, Clone)]
pub struct Chown16Return {}

#[derive(Debug, Clone)]
pub struct ChrootReturn {}

#[derive(Debug, Clone)]
pub struct ClockAdjtimeReturn {}

#[derive(Debug, Clone)]
pub struct ClockAdjtime32Return {}

#[derive(Debug, Clone)]
pub struct ClockGetresReturn {}

#[derive(Debug, Clone)]
pub struct ClockGetresTime32Return {}

#[derive(Debug, Clone)]
pub struct ClockGettimeReturn {
    pub timespec: TimeSpec,
}

#[derive(Debug, Clone)]
pub struct ClockGettime32Return {}

#[derive(Debug, Clone)]
pub struct ClockNanosleepReturn {}

#[derive(Debug, Clone)]
pub struct ClockNanosleepTime32Return {}

#[derive(Debug, Clone)]
pub struct ClockSettimeReturn {}

#[derive(Debug, Clone)]
pub struct ClockSettime32Return {}

#[derive(Debug, Clone)]
pub struct CloneReturn {}

#[derive(Debug, Clone)]
pub struct Clone3Return {}

#[derive(Debug, Clone)]
pub struct CloseReturn {}

#[derive(Debug, Clone)]
pub struct ConnectReturn {}

#[derive(Debug, Clone)]
pub struct CopyFileRangeReturn {}

#[derive(Debug, Clone)]
pub struct CreatReturn {}

#[derive(Debug, Clone)]
pub struct CskyFadvise6464Return {}

#[derive(Debug, Clone)]
pub struct DebugSetcontextReturn {}

#[derive(Debug, Clone)]
pub struct DeleteModuleReturn {}

#[derive(Debug, Clone)]
pub struct DupReturn {}

#[derive(Debug, Clone)]
pub struct Dup2Return {}

#[derive(Debug, Clone)]
pub struct Dup3Return {}

#[derive(Debug, Clone)]
pub struct EpollCreateReturn {}

#[derive(Debug, Clone)]
pub struct EpollCreate1Return {}

#[derive(Debug, Clone)]
pub struct EpollCtlReturn {}

#[derive(Debug, Clone)]
pub struct EpollPwaitReturn {}

#[derive(Debug, Clone)]
pub struct EpollWaitReturn {}

#[derive(Debug, Clone)]
pub struct EventfdReturn {}

#[derive(Debug, Clone)]
pub struct Eventfd2Return {}

#[derive(Debug, Clone)]
pub struct ExecveReturn {}

#[derive(Debug, Clone)]
pub struct ExecveatReturn {}

#[derive(Debug, Clone)]
pub struct ExitReturn {}

#[derive(Debug, Clone)]
pub struct ExitGroupReturn {}

#[derive(Debug, Clone)]
pub struct FaccessatReturn {}

#[derive(Debug, Clone)]
pub struct Fadvise64Return {}

#[derive(Debug, Clone)]
pub struct Fadvise6464Return {}

#[derive(Debug, Clone)]
pub struct Fadvise6464WrapperReturn {}

#[derive(Debug, Clone)]
pub struct FallocateReturn {}

#[derive(Debug, Clone)]
pub struct FanotifyInitReturn {}

#[derive(Debug, Clone)]
pub struct FanotifyMarkReturn {}

#[derive(Debug, Clone)]
pub struct FchdirReturn {}

#[derive(Debug, Clone)]
pub struct FchmodReturn {}

#[derive(Debug, Clone)]
pub struct FchmodatReturn {}

#[derive(Debug, Clone)]
pub struct FchownReturn {}

#[derive(Debug, Clone)]
pub struct Fchown16Return {}

#[derive(Debug, Clone)]
pub struct FchownatReturn {}

#[derive(Debug, Clone)]
pub struct FcntlReturn {}

#[derive(Debug, Clone)]
pub struct Fcntl64Return {}

#[derive(Debug, Clone)]
pub struct FdatasyncReturn {}

#[derive(Debug, Clone)]
pub struct FgetxattrReturn {}

#[derive(Debug, Clone)]
pub struct FinitModuleReturn {}

#[derive(Debug, Clone)]
pub struct FlistxattrReturn {}

#[derive(Debug, Clone)]
pub struct FlockReturn {}

#[derive(Debug, Clone)]
pub struct ForkReturn {}

#[derive(Debug, Clone)]
pub struct FpUdfiexCrtlReturn {}

#[derive(Debug, Clone)]
pub struct FremovexattrReturn {}

#[derive(Debug, Clone)]
pub struct FsconfigReturn {}

#[derive(Debug, Clone)]
pub struct FsetxattrReturn {}

#[derive(Debug, Clone)]
pub struct FsmountReturn {}

#[derive(Debug, Clone)]
pub struct FsopenReturn {}

#[derive(Debug, Clone)]
pub struct FspickReturn {}

#[derive(Debug, Clone)]
pub struct FstatReturn {}

#[derive(Debug, Clone)]
pub struct Fstat64Return {}

#[derive(Debug, Clone)]
pub struct Fstatat64Return {}

#[derive(Debug, Clone)]
pub struct FstatfsReturn {}

#[derive(Debug, Clone)]
pub struct Fstatfs64Return {}

#[derive(Debug, Clone)]
pub struct FsyncReturn {}

#[derive(Debug, Clone)]
pub struct FtruncateReturn {}

#[derive(Debug, Clone)]
pub struct Ftruncate64Return {}

#[derive(Debug, Clone)]
pub struct FutexReturn {}

#[derive(Debug, Clone)]
pub struct FutexTime32Return {}

#[derive(Debug, Clone)]
pub struct FutimesatReturn {}

#[derive(Debug, Clone)]
pub struct FutimesatTime32Return {}

#[derive(Debug, Clone)]
pub struct GetMempolicyReturn {}

#[derive(Debug, Clone)]
pub struct GetRobustListReturn {}

#[derive(Debug, Clone)]
pub struct GetThreadAreaReturn {}

#[derive(Debug, Clone)]
pub struct GetcpuReturn {}

#[derive(Debug, Clone)]
pub struct GetcwdReturn {}

#[derive(Debug, Clone)]
pub struct GetdentsReturn {}

#[derive(Debug, Clone)]
pub struct Getdents64Return {}

#[derive(Debug, Clone)]
pub struct GetdomainnameReturn {}

#[derive(Debug, Clone)]
pub struct GetdtablesizeReturn {}

#[derive(Debug, Clone)]
pub struct GetegidReturn {}

#[derive(Debug, Clone)]
pub struct Getegid16Return {}

#[derive(Debug, Clone)]
pub struct GeteuidReturn {}

#[derive(Debug, Clone)]
pub struct Geteuid16Return {}

#[derive(Debug, Clone)]
pub struct GetgidReturn {}

#[derive(Debug, Clone)]
pub struct Getgid16Return {}

#[derive(Debug, Clone)]
pub struct GetgroupsReturn {}

#[derive(Debug, Clone)]
pub struct Getgroups16Return {}

#[derive(Debug, Clone)]
pub struct GethostnameReturn {}

#[derive(Debug, Clone)]
pub struct GetitimerReturn {}

#[derive(Debug, Clone)]
pub struct GetpagesizeReturn {}

#[derive(Debug, Clone)]
pub struct GetpeernameReturn {}

#[derive(Debug, Clone)]
pub struct GetpgidReturn {}

#[derive(Debug, Clone)]
pub struct GetpgrpReturn {}

#[derive(Debug, Clone)]
pub struct GetpidReturn {}

#[derive(Debug, Clone)]
pub struct GetppidReturn {}

#[derive(Debug, Clone)]
pub struct GetpriorityReturn {}

#[derive(Debug, Clone)]
pub struct GetrandomReturn {}

#[derive(Debug, Clone)]
pub struct GetresgidReturn {}

#[derive(Debug, Clone)]
pub struct Getresgid16Return {}

#[derive(Debug, Clone)]
pub struct GetresuidReturn {}

#[derive(Debug, Clone)]
pub struct Getresuid16Return {}

#[derive(Debug, Clone)]
pub struct GetrlimitReturn {}

#[derive(Debug, Clone)]
pub struct GetrusageReturn {}

#[derive(Debug, Clone)]
pub struct GetsidReturn {}

#[derive(Debug, Clone)]
pub struct GetsocknameReturn {}

#[derive(Debug, Clone)]
pub struct GetsockoptReturn {}

#[derive(Debug, Clone)]
pub struct GettidReturn {}

#[derive(Debug, Clone)]
pub struct GettimeofdayReturn {}

#[derive(Debug, Clone)]
pub struct GetuidReturn {}

#[derive(Debug, Clone)]
pub struct Getuid16Return {}

#[derive(Debug, Clone)]
pub struct GetxattrReturn {}

#[derive(Debug, Clone)]
pub struct GetxgidReturn {}

#[derive(Debug, Clone)]
pub struct GetxpidReturn {}

#[derive(Debug, Clone)]
pub struct GetxuidReturn {}

#[derive(Debug, Clone)]
pub struct InitModuleReturn {}

#[derive(Debug, Clone)]
pub struct InotifyAddWatchReturn {}

#[derive(Debug, Clone)]
pub struct InotifyInitReturn {}

#[derive(Debug, Clone)]
pub struct InotifyInit1Return {}

#[derive(Debug, Clone)]
pub struct InotifyRmWatchReturn {}

#[derive(Debug, Clone)]
pub struct IoCancelReturn {}

#[derive(Debug, Clone)]
pub struct IoDestroyReturn {}

#[derive(Debug, Clone)]
pub struct IoGeteventsReturn {}

#[derive(Debug, Clone)]
pub struct IoGeteventsTime32Return {}

#[derive(Debug, Clone)]
pub struct IoPgeteventsReturn {}

#[derive(Debug, Clone)]
pub struct IoPgeteventsTime32Return {}

#[derive(Debug, Clone)]
pub struct IoSetupReturn {}

#[derive(Debug, Clone)]
pub struct IoSubmitReturn {}

#[derive(Debug, Clone)]
pub struct IoUringEnterReturn {}

#[derive(Debug, Clone)]
pub struct IoUringRegisterReturn {}

#[derive(Debug, Clone)]
pub struct IoUringSetupReturn {}

#[derive(Debug, Clone)]
pub struct IoctlReturn {}

#[derive(Debug, Clone)]
pub struct IopermReturn {}

#[derive(Debug, Clone)]
pub struct IoplReturn {}

#[derive(Debug, Clone)]
pub struct IoprioGetReturn {}

#[derive(Debug, Clone)]
pub struct IoprioSetReturn {}

#[derive(Debug, Clone)]
pub struct IpcReturn {}

#[derive(Debug, Clone)]
pub struct KcmpReturn {}

#[derive(Debug, Clone)]
pub struct KernFeaturesReturn {}

#[derive(Debug, Clone)]
pub struct KexecFileLoadReturn {}

#[derive(Debug, Clone)]
pub struct KexecLoadReturn {}

#[derive(Debug, Clone)]
pub struct KeyctlReturn {}

#[derive(Debug, Clone)]
pub struct KillReturn {}

#[derive(Debug, Clone)]
pub struct LchownReturn {}

#[derive(Debug, Clone)]
pub struct Lchown16Return {}

#[derive(Debug, Clone)]
pub struct LgetxattrReturn {}

#[derive(Debug, Clone)]
pub struct LinkReturn {}

#[derive(Debug, Clone)]
pub struct LinkatReturn {}

#[derive(Debug, Clone)]
pub struct ListenReturn {}

#[derive(Debug, Clone)]
pub struct ListxattrReturn {}

#[derive(Debug, Clone)]
pub struct LlistxattrReturn {}

#[derive(Debug, Clone)]
pub struct LlseekReturn {}

#[derive(Debug, Clone)]
pub struct LookupDcookieReturn {}

#[derive(Debug, Clone)]
pub struct LremovexattrReturn {}

#[derive(Debug, Clone)]
pub struct LseekReturn {}

#[derive(Debug, Clone)]
pub struct LsetxattrReturn {}

#[derive(Debug, Clone)]
pub struct LstatReturn {}

#[derive(Debug, Clone)]
pub struct Lstat64Return {}

#[derive(Debug, Clone)]
pub struct MadviseReturn {}

#[derive(Debug, Clone)]
pub struct MbindReturn {}

#[derive(Debug, Clone)]
pub struct MembarrierReturn {}

#[derive(Debug, Clone)]
pub struct MemfdCreateReturn {}

#[derive(Debug, Clone)]
pub struct MemoryOrderingReturn {}

#[derive(Debug, Clone)]
pub struct MigratePagesReturn {}

#[derive(Debug, Clone)]
pub struct MincoreReturn {}

#[derive(Debug, Clone)]
pub struct MipsMmapReturn {}

#[derive(Debug, Clone)]
pub struct MipsMmap2Return {}

#[derive(Debug, Clone)]
pub struct MkdirReturn {}

#[derive(Debug, Clone)]
pub struct MkdiratReturn {}

#[derive(Debug, Clone)]
pub struct MknodReturn {}

#[derive(Debug, Clone)]
pub struct MknodatReturn {}

#[derive(Debug, Clone)]
pub struct MlockReturn {}

#[derive(Debug, Clone)]
pub struct Mlock2Return {}

#[derive(Debug, Clone)]
pub struct MlockallReturn {}

#[derive(Debug, Clone)]
pub struct MmapReturn {
    address: *mut c_void,
}

#[derive(Debug, Clone)]
pub struct Mmap2Return {}

#[derive(Debug, Clone)]
pub struct MmapPgoffReturn {}

#[derive(Debug, Clone)]
pub struct ModifyLdtReturn {}

#[derive(Debug, Clone)]
pub struct MountReturn {}

#[derive(Debug, Clone)]
pub struct MoveMountReturn {}

#[derive(Debug, Clone)]
pub struct MovePagesReturn {}

#[derive(Debug, Clone)]
pub struct MprotectReturn {}

#[derive(Debug, Clone)]
pub struct MqGetsetattrReturn {}

#[derive(Debug, Clone)]
pub struct MqNotifyReturn {}

#[derive(Debug, Clone)]
pub struct MqOpenReturn {}

#[derive(Debug, Clone)]
pub struct MqTimedreceiveReturn {}

#[derive(Debug, Clone)]
pub struct MqTimedreceiveTime32Return {}

#[derive(Debug, Clone)]
pub struct MqTimedsendReturn {}

#[derive(Debug, Clone)]
pub struct MqTimedsendTime32Return {}

#[derive(Debug, Clone)]
pub struct MqUnlinkReturn {}

#[derive(Debug, Clone)]
pub struct MremapReturn {}

#[derive(Debug, Clone)]
pub struct MsgctlReturn {}

#[derive(Debug, Clone)]
pub struct MsggetReturn {}

#[derive(Debug, Clone)]
pub struct MsgrcvReturn {}

#[derive(Debug, Clone)]
pub struct MsgsndReturn {}

#[derive(Debug, Clone)]
pub struct MsyncReturn {}

#[derive(Debug, Clone)]
pub struct MunlockReturn {}

#[derive(Debug, Clone)]
pub struct MunlockallReturn {}

#[derive(Debug, Clone)]
pub struct MunmapReturn {}

#[derive(Debug, Clone)]
pub struct NameToHandleAtReturn {}

#[derive(Debug, Clone)]
pub struct NanosleepReturn {}

#[derive(Debug, Clone)]
pub struct NanosleepTime32Return {}

#[derive(Debug, Clone)]
pub struct NewfstatReturn {}

#[derive(Debug, Clone)]
pub struct NewfstatatReturn {}

#[derive(Debug, Clone)]
pub struct NewlstatReturn {}

#[derive(Debug, Clone)]
pub struct NewstatReturn {}

#[derive(Debug, Clone)]
pub struct NewunameReturn {}

#[derive(Debug, Clone)]
pub struct NiSyscallReturn {}

#[derive(Debug, Clone)]
pub struct NiceReturn {}

#[derive(Debug, Clone)]
pub struct NisSyscallReturn {}

#[derive(Debug, Clone)]
pub struct OldAdjtimexReturn {}

#[derive(Debug, Clone)]
pub struct OldGetrlimitReturn {}

#[derive(Debug, Clone)]
pub struct OldMmapReturn {}

#[derive(Debug, Clone)]
pub struct OldMsgctlReturn {}

#[derive(Debug, Clone)]
pub struct OldReaddirReturn {}

#[derive(Debug, Clone)]
pub struct OldSelectReturn {}

#[derive(Debug, Clone)]
pub struct OldSemctlReturn {}

#[derive(Debug, Clone)]
pub struct OldShmctlReturn {}

#[derive(Debug, Clone)]
pub struct OldumountReturn {}

#[derive(Debug, Clone)]
pub struct OldunameReturn {}

#[derive(Debug, Clone)]
pub struct OpenReturn {}

#[derive(Debug, Clone)]
pub struct OpenByHandleAtReturn {}

#[derive(Debug, Clone)]
pub struct OpenTreeReturn {}

#[derive(Debug, Clone)]
pub struct OpenatReturn {
    file_descriptor: i32,
}

#[derive(Debug, Clone)]
pub struct Openat2Return {}

#[derive(Debug, Clone)]
pub struct OsfBrkReturn {}

#[derive(Debug, Clone)]
pub struct OsfFstatReturn {}

#[derive(Debug, Clone)]
pub struct OsfFstatfsReturn {}

#[derive(Debug, Clone)]
pub struct OsfFstatfs64Return {}

#[derive(Debug, Clone)]
pub struct OsfGetdirentriesReturn {}

#[derive(Debug, Clone)]
pub struct OsfGetdomainnameReturn {}

#[derive(Debug, Clone)]
pub struct OsfGetpriorityReturn {}

#[derive(Debug, Clone)]
pub struct OsfGetrusageReturn {}

#[derive(Debug, Clone)]
pub struct OsfGetsysinfoReturn {}

#[derive(Debug, Clone)]
pub struct OsfGettimeofdayReturn {}

#[derive(Debug, Clone)]
pub struct OsfLstatReturn {}

#[derive(Debug, Clone)]
pub struct OsfMmapReturn {}

#[derive(Debug, Clone)]
pub struct OsfMountReturn {}

#[derive(Debug, Clone)]
pub struct OsfProplistSyscallReturn {}

#[derive(Debug, Clone)]
pub struct OsfReadvReturn {}

#[derive(Debug, Clone)]
pub struct OsfSelectReturn {}

#[derive(Debug, Clone)]
pub struct OsfSetProgramAttributesReturn {}

#[derive(Debug, Clone)]
pub struct OsfSetsysinfoReturn {}

#[derive(Debug, Clone)]
pub struct OsfSettimeofdayReturn {}

#[derive(Debug, Clone)]
pub struct OsfSigactionReturn {}

#[derive(Debug, Clone)]
pub struct OsfSigprocmaskReturn {}

#[derive(Debug, Clone)]
pub struct OsfSigstackReturn {}

#[derive(Debug, Clone)]
pub struct OsfStatReturn {}

#[derive(Debug, Clone)]
pub struct OsfStatfsReturn {}

#[derive(Debug, Clone)]
pub struct OsfStatfs64Return {}

#[derive(Debug, Clone)]
pub struct OsfSysinfoReturn {}

#[derive(Debug, Clone)]
pub struct OsfUsleepThreadReturn {}

#[derive(Debug, Clone)]
pub struct OsfUtimesReturn {}

#[derive(Debug, Clone)]
pub struct OsfUtsnameReturn {}

#[derive(Debug, Clone)]
pub struct OsfWait4Return {}

#[derive(Debug, Clone)]
pub struct OsfWritevReturn {}

#[derive(Debug, Clone)]
pub struct PauseReturn {}

#[derive(Debug, Clone)]
pub struct PciconfigIobaseReturn {}

#[derive(Debug, Clone)]
pub struct PciconfigReadReturn {}

#[derive(Debug, Clone)]
pub struct PciconfigWriteReturn {}

#[derive(Debug, Clone)]
pub struct PerfEventOpenReturn {}

#[derive(Debug, Clone)]
pub struct PersonalityReturn {}

#[derive(Debug, Clone)]
pub struct PidfdGetfdReturn {}

#[derive(Debug, Clone)]
pub struct PidfdOpenReturn {}

#[derive(Debug, Clone)]
pub struct PidfdSendSignalReturn {}

#[derive(Debug, Clone)]
pub struct PipeReturn {}

#[derive(Debug, Clone)]
pub struct Pipe2Return {}

#[derive(Debug, Clone)]
pub struct PivotRootReturn {}

#[derive(Debug, Clone)]
pub struct PkeyAllocReturn {}

#[derive(Debug, Clone)]
pub struct PkeyFreeReturn {}

#[derive(Debug, Clone)]
pub struct PkeyMprotectReturn {}

#[derive(Debug, Clone)]
pub struct PollReturn {}

#[derive(Debug, Clone)]
pub struct PpollReturn {}

#[derive(Debug, Clone)]
pub struct PpollTime32Return {}

#[derive(Debug, Clone)]
pub struct PrctlReturn {}

#[derive(Debug, Clone)]
pub struct Pread64Return {}

#[derive(Debug, Clone)]
pub struct PreadvReturn {}

#[derive(Debug, Clone)]
pub struct Preadv2Return {}

#[derive(Debug, Clone)]
pub struct Prlimit64Return {}

#[derive(Debug, Clone)]
pub struct ProcessVmReadvReturn {}

#[derive(Debug, Clone)]
pub struct ProcessVmWritevReturn {}

#[derive(Debug, Clone)]
pub struct Pselect6Return {}

#[derive(Debug, Clone)]
pub struct Pselect6Time32Return {}

#[derive(Debug, Clone)]
pub struct PtraceReturn {}

#[derive(Debug, Clone)]
pub struct Pwrite64Return {}

#[derive(Debug, Clone)]
pub struct PwritevReturn {}

#[derive(Debug, Clone)]
pub struct Pwritev2Return {}

#[derive(Debug, Clone)]
pub struct QuotactlReturn {}

#[derive(Debug, Clone)]
pub struct ReadReturn {}

#[derive(Debug, Clone)]
pub struct ReadaheadReturn {}

#[derive(Debug, Clone)]
pub struct ReadlinkReturn {}

#[derive(Debug, Clone)]
pub struct ReadlinkatReturn {}

#[derive(Debug, Clone)]
pub struct ReadvReturn {}

#[derive(Debug, Clone)]
pub struct RebootReturn {}

#[derive(Debug, Clone)]
pub struct RecvReturn {}

#[derive(Debug, Clone)]
pub struct RecvfromReturn {}

#[derive(Debug, Clone)]
pub struct RecvmmsgReturn {}

#[derive(Debug, Clone)]
pub struct RecvmmsgTime32Return {}

#[derive(Debug, Clone)]
pub struct RecvmsgReturn {}

#[derive(Debug, Clone)]
pub struct RemapFilePagesReturn {}

#[derive(Debug, Clone)]
pub struct RemovexattrReturn {}

#[derive(Debug, Clone)]
pub struct RenameReturn {}

#[derive(Debug, Clone)]
pub struct RenameatReturn {}

#[derive(Debug, Clone)]
pub struct Renameat2Return {}

#[derive(Debug, Clone)]
pub struct RequestKeyReturn {}

#[derive(Debug, Clone)]
pub struct RestartSyscallReturn {}

#[derive(Debug, Clone)]
pub struct RiscvFlushIcacheReturn {}

#[derive(Debug, Clone)]
pub struct RmdirReturn {}

#[derive(Debug, Clone)]
pub struct RseqReturn {}

#[derive(Debug, Clone)]
pub struct RtSigactionReturn {}

#[derive(Debug, Clone)]
pub struct RtSigpendingReturn {}

#[derive(Debug, Clone)]
pub struct RtSigprocmaskReturn {}

#[derive(Debug, Clone)]
pub struct RtSigqueueinfoReturn {}

#[derive(Debug, Clone)]
pub struct RtSigreturnReturn {}

#[derive(Debug, Clone)]
pub struct RtSigsuspendReturn {}

#[derive(Debug, Clone)]
pub struct RtSigtimedwaitReturn {}

#[derive(Debug, Clone)]
pub struct RtSigtimedwaitTime32Return {}

#[derive(Debug, Clone)]
pub struct RtTgsigqueueinfoReturn {}

#[derive(Debug, Clone)]
pub struct RtasReturn {}

#[derive(Debug, Clone)]
pub struct S390GuardedStorageReturn {}

#[derive(Debug, Clone)]
pub struct S390IpcReturn {}

#[derive(Debug, Clone)]
pub struct S390PciMmioReadReturn {}

#[derive(Debug, Clone)]
pub struct S390PciMmioWriteReturn {}

#[derive(Debug, Clone)]
pub struct S390PersonalityReturn {}

#[derive(Debug, Clone)]
pub struct S390RuntimeInstrReturn {}

#[derive(Debug, Clone)]
pub struct S390SthyiReturn {}

#[derive(Debug, Clone)]
pub struct SchedGetPriorityMaxReturn {}

#[derive(Debug, Clone)]
pub struct SchedGetPriorityMinReturn {}

#[derive(Debug, Clone)]
pub struct SchedGetaffinityReturn {}

#[derive(Debug, Clone)]
pub struct SchedGetattrReturn {}

#[derive(Debug, Clone)]
pub struct SchedGetparamReturn {}

#[derive(Debug, Clone)]
pub struct SchedGetschedulerReturn {}

#[derive(Debug, Clone)]
pub struct SchedRrGetIntervalReturn {}

#[derive(Debug, Clone)]
pub struct SchedRrGetIntervalTime32Return {}

#[derive(Debug, Clone)]
pub struct SchedSetaffinityReturn {}

#[derive(Debug, Clone)]
pub struct SchedSetattrReturn {}

#[derive(Debug, Clone)]
pub struct SchedSetparamReturn {}

#[derive(Debug, Clone)]
pub struct SchedSetschedulerReturn {}

#[derive(Debug, Clone)]
pub struct SchedYieldReturn {}

#[derive(Debug, Clone)]
pub struct SeccompReturn {}

#[derive(Debug, Clone)]
pub struct SelectReturn {}

#[derive(Debug, Clone)]
pub struct SemctlReturn {}

#[derive(Debug, Clone)]
pub struct SemgetReturn {}

#[derive(Debug, Clone)]
pub struct SemopReturn {}

#[derive(Debug, Clone)]
pub struct SemtimedopReturn {}

#[derive(Debug, Clone)]
pub struct SemtimedopTime32Return {}

#[derive(Debug, Clone)]
pub struct SendReturn {}

#[derive(Debug, Clone)]
pub struct SendfileReturn {}

#[derive(Debug, Clone)]
pub struct Sendfile64Return {}

#[derive(Debug, Clone)]
pub struct SendmmsgReturn {}

#[derive(Debug, Clone)]
pub struct SendmsgReturn {}

#[derive(Debug, Clone)]
pub struct SendtoReturn {}

#[derive(Debug, Clone)]
pub struct SetMempolicyReturn {}

#[derive(Debug, Clone)]
pub struct SetRobustListReturn {}

#[derive(Debug, Clone)]
pub struct SetThreadAreaReturn {}

#[derive(Debug, Clone)]
pub struct SetTidAddressReturn {}

#[derive(Debug, Clone)]
pub struct SetdomainnameReturn {}

#[derive(Debug, Clone)]
pub struct SetfsgidReturn {}

#[derive(Debug, Clone)]
pub struct Setfsgid16Return {}

#[derive(Debug, Clone)]
pub struct SetfsuidReturn {}

#[derive(Debug, Clone)]
pub struct Setfsuid16Return {}

#[derive(Debug, Clone)]
pub struct SetgidReturn {}

#[derive(Debug, Clone)]
pub struct Setgid16Return {}

#[derive(Debug, Clone)]
pub struct SetgroupsReturn {}

#[derive(Debug, Clone)]
pub struct Setgroups16Return {}

#[derive(Debug, Clone)]
pub struct SethaeReturn {}

#[derive(Debug, Clone)]
pub struct SethostnameReturn {}

#[derive(Debug, Clone)]
pub struct SetitimerReturn {}

#[derive(Debug, Clone)]
pub struct SetnsReturn {}

#[derive(Debug, Clone)]
pub struct SetpgidReturn {}

#[derive(Debug, Clone)]
pub struct SetpriorityReturn {}

#[derive(Debug, Clone)]
pub struct SetregidReturn {}

#[derive(Debug, Clone)]
pub struct Setregid16Return {}

#[derive(Debug, Clone)]
pub struct SetresgidReturn {}

#[derive(Debug, Clone)]
pub struct Setresgid16Return {}

#[derive(Debug, Clone)]
pub struct SetresuidReturn {}

#[derive(Debug, Clone)]
pub struct Setresuid16Return {}

#[derive(Debug, Clone)]
pub struct SetreuidReturn {}

#[derive(Debug, Clone)]
pub struct Setreuid16Return {}

#[derive(Debug, Clone)]
pub struct SetrlimitReturn {}

#[derive(Debug, Clone)]
pub struct SetsidReturn {}

#[derive(Debug, Clone)]
pub struct SetsockoptReturn {}

#[derive(Debug, Clone)]
pub struct SettimeofdayReturn {}

#[derive(Debug, Clone)]
pub struct SetuidReturn {}

#[derive(Debug, Clone)]
pub struct Setuid16Return {}

#[derive(Debug, Clone)]
pub struct SetxattrReturn {}

#[derive(Debug, Clone)]
pub struct SgetmaskReturn {}

#[derive(Debug, Clone)]
pub struct ShmatReturn {}

#[derive(Debug, Clone)]
pub struct ShmctlReturn {}

#[derive(Debug, Clone)]
pub struct ShmdtReturn {}

#[derive(Debug, Clone)]
pub struct ShmgetReturn {}

#[derive(Debug, Clone)]
pub struct ShutdownReturn {}

#[derive(Debug, Clone)]
pub struct SigactionReturn {}

#[derive(Debug, Clone)]
pub struct SigaltstackReturn {}

#[derive(Debug, Clone)]
pub struct SignalReturn {}

#[derive(Debug, Clone)]
pub struct SignalfdReturn {}

#[derive(Debug, Clone)]
pub struct Signalfd4Return {}

#[derive(Debug, Clone)]
pub struct SigpendingReturn {}

#[derive(Debug, Clone)]
pub struct SigprocmaskReturn {}

#[derive(Debug, Clone)]
pub struct SigreturnReturn {}

#[derive(Debug, Clone)]
pub struct SigsuspendReturn {}

#[derive(Debug, Clone)]
pub struct SocketReturn {}

#[derive(Debug, Clone)]
pub struct SocketcallReturn {}

#[derive(Debug, Clone)]
pub struct SocketpairReturn {}

#[derive(Debug, Clone)]
pub struct Sparc64PersonalityReturn {}

#[derive(Debug, Clone)]
pub struct SparcAdjtimexReturn {}

#[derive(Debug, Clone)]
pub struct SparcClockAdjtimeReturn {}

#[derive(Debug, Clone)]
pub struct SparcIpcReturn {}

#[derive(Debug, Clone)]
pub struct SparcPipeReturn {}

#[derive(Debug, Clone)]
pub struct SparcRemapFilePagesReturn {}

#[derive(Debug, Clone)]
pub struct SparcSigactionReturn {}

#[derive(Debug, Clone)]
pub struct SpliceReturn {}

#[derive(Debug, Clone)]
pub struct SpuCreateReturn {}

#[derive(Debug, Clone)]
pub struct SpuRunReturn {}

#[derive(Debug, Clone)]
pub struct SsetmaskReturn {}

#[derive(Debug, Clone)]
pub struct StatReturn {
    stat: StatStruct,
}

#[derive(Debug, Clone)]
pub struct Stat64Return {}

#[derive(Debug, Clone)]
pub struct StatfsReturn {}

#[derive(Debug, Clone)]
pub struct Statfs64Return {}

#[derive(Debug, Clone)]
pub struct StatxReturn {}

#[derive(Debug, Clone)]
pub struct StimeReturn {}

#[derive(Debug, Clone)]
pub struct Stime32Return {}

#[derive(Debug, Clone)]
pub struct SubpageProtReturn {}

#[derive(Debug, Clone)]
pub struct SwapcontextReturn {}

#[derive(Debug, Clone)]
pub struct SwapoffReturn {}

#[derive(Debug, Clone)]
pub struct SwaponReturn {}

#[derive(Debug, Clone)]
pub struct SwitchEndianReturn {}

#[derive(Debug, Clone)]
pub struct SymlinkReturn {}

#[derive(Debug, Clone)]
pub struct SymlinkatReturn {}

#[derive(Debug, Clone)]
pub struct SyncReturn {}

#[derive(Debug, Clone)]
pub struct SyncFileRangeReturn {}

#[derive(Debug, Clone)]
pub struct SyncFileRange2Return {}

#[derive(Debug, Clone)]
pub struct SyncfsReturn {}

#[derive(Debug, Clone)]
pub struct SysctlReturn {}

#[derive(Debug, Clone)]
pub struct SysfsReturn {}

#[derive(Debug, Clone)]
pub struct SysinfoReturn {}

#[derive(Debug, Clone)]
pub struct SyslogReturn {}

#[derive(Debug, Clone)]
pub struct SysmipsReturn {}

#[derive(Debug, Clone)]
pub struct TeeReturn {}

#[derive(Debug, Clone)]
pub struct TgkillReturn {}

#[derive(Debug, Clone)]
pub struct TimeReturn {}

#[derive(Debug, Clone)]
pub struct Time32Return {}

#[derive(Debug, Clone)]
pub struct TimerCreateReturn {}

#[derive(Debug, Clone)]
pub struct TimerDeleteReturn {}

#[derive(Debug, Clone)]
pub struct TimerGetoverrunReturn {}

#[derive(Debug, Clone)]
pub struct TimerGettimeReturn {}

#[derive(Debug, Clone)]
pub struct TimerGettime32Return {}

#[derive(Debug, Clone)]
pub struct TimerSettimeReturn {}

#[derive(Debug, Clone)]
pub struct TimerSettime32Return {}

#[derive(Debug, Clone)]
pub struct TimerfdCreateReturn {}

#[derive(Debug, Clone)]
pub struct TimerfdGettimeReturn {}

#[derive(Debug, Clone)]
pub struct TimerfdGettime32Return {}

#[derive(Debug, Clone)]
pub struct TimerfdSettimeReturn {}

#[derive(Debug, Clone)]
pub struct TimerfdSettime32Return {}

#[derive(Debug, Clone)]
pub struct TimesReturn {}

#[derive(Debug, Clone)]
pub struct TkillReturn {}

#[derive(Debug, Clone)]
pub struct TruncateReturn {}

#[derive(Debug, Clone)]
pub struct Truncate64Return {}

#[derive(Debug, Clone)]
pub struct UmaskReturn {}

#[derive(Debug, Clone)]
pub struct UmountReturn {}

#[derive(Debug, Clone)]
pub struct UnameReturn {}

#[derive(Debug, Clone)]
pub struct UnlinkReturn {}

#[derive(Debug, Clone)]
pub struct UnlinkatReturn {}

#[derive(Debug, Clone)]
pub struct UnshareReturn {}

#[derive(Debug, Clone)]
pub struct UselibReturn {}

#[derive(Debug, Clone)]
pub struct UserfaultfdReturn {}

#[derive(Debug, Clone)]
pub struct UstatReturn {}

#[derive(Debug, Clone)]
pub struct UtimeReturn {}

#[derive(Debug, Clone)]
pub struct Utime32Return {}

#[derive(Debug, Clone)]
pub struct UtimensatReturn {}

#[derive(Debug, Clone)]
pub struct UtimensatTime32Return {}

#[derive(Debug, Clone)]
pub struct UtimesReturn {}

#[derive(Debug, Clone)]
pub struct UtimesTime32Return {}

#[derive(Debug, Clone)]
pub struct UtrapInstallReturn {}

#[derive(Debug, Clone)]
pub struct VforkReturn {}

#[derive(Debug, Clone)]
pub struct VhangupReturn {}

#[derive(Debug, Clone)]
pub struct Vm86Return {}

#[derive(Debug, Clone)]
pub struct Vm86oldReturn {}

#[derive(Debug, Clone)]
pub struct VmspliceReturn {}

#[derive(Debug, Clone)]
pub struct Wait4Return {}

#[derive(Debug, Clone)]
pub struct WaitidReturn {}

#[derive(Debug, Clone)]
pub struct WaitpidReturn {}

#[derive(Debug, Clone)]
pub struct WriteReturn {}

#[derive(Debug, Clone)]
pub struct WritevReturn {}

impl AcceptReturn {
    pub fn from_enter_event(
        enter: Accept,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(AcceptReturn {})
    }
}

impl Accept4Return {
    pub fn from_enter_event(
        enter: Accept4,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Accept4Return {})
    }
}

impl AccessReturn {
    pub fn from_enter_event(
        enter: Access,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(AccessReturn {})
    }
}

impl AcctReturn {
    pub fn from_enter_event(
        enter: Acct,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(AcctReturn {})
    }
}

impl AddKeyReturn {
    pub fn from_enter_event(
        enter: AddKey,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(AddKeyReturn {})
    }
}

impl AdjtimexReturn {
    pub fn from_enter_event(
        enter: Adjtimex,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(AdjtimexReturn {})
    }
}

impl AdjtimexTime32Return {
    pub fn from_enter_event(
        enter: AdjtimexTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(AdjtimexTime32Return {})
    }
}

impl AlarmReturn {
    pub fn from_enter_event(
        enter: Alarm,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(AlarmReturn {})
    }
}

impl AlphaPipeReturn {
    pub fn from_enter_event(
        enter: AlphaPipe,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(AlphaPipeReturn {})
    }
}

impl ArcGettlsReturn {
    pub fn from_enter_event(
        enter: ArcGettls,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ArcGettlsReturn {})
    }
}

impl ArcSettlsReturn {
    pub fn from_enter_event(
        enter: ArcSettls,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ArcSettlsReturn {})
    }
}

impl ArcUsrCmpxchgReturn {
    pub fn from_enter_event(
        enter: ArcUsrCmpxchg,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ArcUsrCmpxchgReturn {})
    }
}

impl Arch32Ftruncate64Return {
    pub fn from_enter_event(
        enter: Arch32Ftruncate64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arch32Ftruncate64Return {})
    }
}

impl Arch32LlseekReturn {
    pub fn from_enter_event(
        enter: Arch32Llseek,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arch32LlseekReturn {})
    }
}

impl Arch32PersonalityReturn {
    pub fn from_enter_event(
        enter: Arch32Personality,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arch32PersonalityReturn {})
    }
}

impl Arch32PreadReturn {
    pub fn from_enter_event(
        enter: Arch32Pread,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arch32PreadReturn {})
    }
}

impl Arch32PwriteReturn {
    pub fn from_enter_event(
        enter: Arch32Pwrite,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arch32PwriteReturn {})
    }
}

impl Arch32SigactionReturn {
    pub fn from_enter_event(
        enter: Arch32Sigaction,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arch32SigactionReturn {})
    }
}

impl Arch32Truncate64Return {
    pub fn from_enter_event(
        enter: Arch32Truncate64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arch32Truncate64Return {})
    }
}

impl Arch64MremapReturn {
    pub fn from_enter_event(
        enter: Arch64Mremap,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arch64MremapReturn {})
    }
}

impl Arch64MunmapReturn {
    pub fn from_enter_event(
        enter: Arch64Munmap,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arch64MunmapReturn {})
    }
}

impl ArchPrctlReturn {
    pub fn from_enter_event(
        enter: ArchPrctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ArchPrctlReturn {})
    }
}

impl Arm64PersonalityReturn {
    pub fn from_enter_event(
        enter: Arm64Personality,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Arm64PersonalityReturn {})
    }
}

impl BdflushReturn {
    pub fn from_enter_event(
        enter: Bdflush,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(BdflushReturn {})
    }
}

impl BindReturn {
    pub fn from_enter_event(
        enter: Bind,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(BindReturn {})
    }
}

impl BpfReturn {
    pub fn from_enter_event(
        enter: Bpf,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(BpfReturn {})
    }
}

impl BrkReturn {
    pub fn from_enter_event(
        enter: Brk,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(BrkReturn {})
    }
}

impl CachectlReturn {
    pub fn from_enter_event(
        enter: Cachectl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(CachectlReturn {})
    }
}

impl CacheflushReturn {
    pub fn from_enter_event(
        enter: Cacheflush,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(CacheflushReturn {})
    }
}

impl CapgetReturn {
    pub fn from_enter_event(
        enter: Capget,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(CapgetReturn {})
    }
}

impl CapsetReturn {
    pub fn from_enter_event(
        enter: Capset,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(CapsetReturn {})
    }
}

impl ChdirReturn {
    pub fn from_enter_event(
        enter: Chdir,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ChdirReturn {})
    }
}

impl ChmodReturn {
    pub fn from_enter_event(
        enter: Chmod,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ChmodReturn {})
    }
}

impl ChownReturn {
    pub fn from_enter_event(
        enter: Chown,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ChownReturn {})
    }
}

impl Chown16Return {
    pub fn from_enter_event(
        enter: Chown16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Chown16Return {})
    }
}

impl ChrootReturn {
    pub fn from_enter_event(
        enter: Chroot,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ChrootReturn {})
    }
}

impl ClockAdjtimeReturn {
    pub fn from_enter_event(
        enter: ClockAdjtime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockAdjtimeReturn {})
    }
}

impl ClockAdjtime32Return {
    pub fn from_enter_event(
        enter: ClockAdjtime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockAdjtime32Return {})
    }
}

impl ClockGetresReturn {
    pub fn from_enter_event(
        enter: ClockGetres,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockGetresReturn {})
    }
}

impl ClockGetresTime32Return {
    pub fn from_enter_event(
        enter: ClockGetresTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockGetresTime32Return {})
    }
}

impl ClockGettimeReturn {
    pub fn from_enter_event(
        enter: ClockGettime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockGettimeReturn {
            timespec: FromStoppedProcess::from_process(process, enter.timestamp as u64)?,
        })
    }
}

impl ClockGettime32Return {
    pub fn from_enter_event(
        enter: ClockGettime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockGettime32Return {})
    }
}

impl ClockNanosleepReturn {
    pub fn from_enter_event(
        enter: ClockNanosleep,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockNanosleepReturn {})
    }
}

impl ClockNanosleepTime32Return {
    pub fn from_enter_event(
        enter: ClockNanosleepTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockNanosleepTime32Return {})
    }
}

impl ClockSettimeReturn {
    pub fn from_enter_event(
        enter: ClockSettime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockSettimeReturn {})
    }
}

impl ClockSettime32Return {
    pub fn from_enter_event(
        enter: ClockSettime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ClockSettime32Return {})
    }
}

impl CloneReturn {
    pub fn from_enter_event(
        enter: Clone,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(CloneReturn {})
    }
}

impl Clone3Return {
    pub fn from_enter_event(
        enter: Clone3,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Clone3Return {})
    }
}

impl CloseReturn {
    pub fn from_enter_event(
        enter: Close,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(CloseReturn {})
    }
}

impl ConnectReturn {
    pub fn from_enter_event(
        enter: Connect,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ConnectReturn {})
    }
}

impl CopyFileRangeReturn {
    pub fn from_enter_event(
        enter: CopyFileRange,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(CopyFileRangeReturn {})
    }
}

impl CreatReturn {
    pub fn from_enter_event(
        enter: Creat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(CreatReturn {})
    }
}

impl CskyFadvise6464Return {
    pub fn from_enter_event(
        enter: CskyFadvise6464,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(CskyFadvise6464Return {})
    }
}

impl DebugSetcontextReturn {
    pub fn from_enter_event(
        enter: DebugSetcontext,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(DebugSetcontextReturn {})
    }
}

impl DeleteModuleReturn {
    pub fn from_enter_event(
        enter: DeleteModule,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(DeleteModuleReturn {})
    }
}

impl DupReturn {
    pub fn from_enter_event(
        enter: Dup,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(DupReturn {})
    }
}

impl Dup2Return {
    pub fn from_enter_event(
        enter: Dup2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Dup2Return {})
    }
}

impl Dup3Return {
    pub fn from_enter_event(
        enter: Dup3,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Dup3Return {})
    }
}

impl EpollCreateReturn {
    pub fn from_enter_event(
        enter: EpollCreate,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(EpollCreateReturn {})
    }
}

impl EpollCreate1Return {
    pub fn from_enter_event(
        enter: EpollCreate1,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(EpollCreate1Return {})
    }
}

impl EpollCtlReturn {
    pub fn from_enter_event(
        enter: EpollCtl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(EpollCtlReturn {})
    }
}

impl EpollPwaitReturn {
    pub fn from_enter_event(
        enter: EpollPwait,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(EpollPwaitReturn {})
    }
}

impl EpollWaitReturn {
    pub fn from_enter_event(
        enter: EpollWait,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(EpollWaitReturn {})
    }
}

impl EventfdReturn {
    pub fn from_enter_event(
        enter: Eventfd,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(EventfdReturn {})
    }
}

impl Eventfd2Return {
    pub fn from_enter_event(
        enter: Eventfd2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Eventfd2Return {})
    }
}

impl ExecveReturn {
    pub fn from_enter_event(
        enter: Execve,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ExecveReturn {})
    }
}

impl ExecveatReturn {
    pub fn from_enter_event(
        enter: Execveat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ExecveatReturn {})
    }
}

impl ExitReturn {
    pub fn from_enter_event(
        enter: Exit,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ExitReturn {})
    }
}

impl ExitGroupReturn {
    pub fn from_enter_event(
        enter: ExitGroup,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ExitGroupReturn {})
    }
}

impl FaccessatReturn {
    pub fn from_enter_event(
        enter: Faccessat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FaccessatReturn {})
    }
}

impl Fadvise64Return {
    pub fn from_enter_event(
        enter: Fadvise64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Fadvise64Return {})
    }
}

impl Fadvise6464Return {
    pub fn from_enter_event(
        enter: Fadvise6464,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Fadvise6464Return {})
    }
}

impl Fadvise6464WrapperReturn {
    pub fn from_enter_event(
        enter: Fadvise6464Wrapper,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Fadvise6464WrapperReturn {})
    }
}

impl FallocateReturn {
    pub fn from_enter_event(
        enter: Fallocate,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FallocateReturn {})
    }
}

impl FanotifyInitReturn {
    pub fn from_enter_event(
        enter: FanotifyInit,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FanotifyInitReturn {})
    }
}

impl FanotifyMarkReturn {
    pub fn from_enter_event(
        enter: FanotifyMark,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FanotifyMarkReturn {})
    }
}

impl FchdirReturn {
    pub fn from_enter_event(
        enter: Fchdir,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FchdirReturn {})
    }
}

impl FchmodReturn {
    pub fn from_enter_event(
        enter: Fchmod,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FchmodReturn {})
    }
}

impl FchmodatReturn {
    pub fn from_enter_event(
        enter: Fchmodat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FchmodatReturn {})
    }
}

impl FchownReturn {
    pub fn from_enter_event(
        enter: Fchown,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FchownReturn {})
    }
}

impl Fchown16Return {
    pub fn from_enter_event(
        enter: Fchown16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Fchown16Return {})
    }
}

impl FchownatReturn {
    pub fn from_enter_event(
        enter: Fchownat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FchownatReturn {})
    }
}

impl FcntlReturn {
    pub fn from_enter_event(
        enter: Fcntl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FcntlReturn {})
    }
}

impl Fcntl64Return {
    pub fn from_enter_event(
        enter: Fcntl64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Fcntl64Return {})
    }
}

impl FdatasyncReturn {
    pub fn from_enter_event(
        enter: Fdatasync,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FdatasyncReturn {})
    }
}

impl FgetxattrReturn {
    pub fn from_enter_event(
        enter: Fgetxattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FgetxattrReturn {})
    }
}

impl FinitModuleReturn {
    pub fn from_enter_event(
        enter: FinitModule,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FinitModuleReturn {})
    }
}

impl FlistxattrReturn {
    pub fn from_enter_event(
        enter: Flistxattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FlistxattrReturn {})
    }
}

impl FlockReturn {
    pub fn from_enter_event(
        enter: Flock,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FlockReturn {})
    }
}

impl ForkReturn {
    pub fn from_enter_event(
        enter: Fork,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ForkReturn {})
    }
}

impl FpUdfiexCrtlReturn {
    pub fn from_enter_event(
        enter: FpUdfiexCrtl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FpUdfiexCrtlReturn {})
    }
}

impl FremovexattrReturn {
    pub fn from_enter_event(
        enter: Fremovexattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FremovexattrReturn {})
    }
}

impl FsconfigReturn {
    pub fn from_enter_event(
        enter: Fsconfig,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FsconfigReturn {})
    }
}

impl FsetxattrReturn {
    pub fn from_enter_event(
        enter: Fsetxattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FsetxattrReturn {})
    }
}

impl FsmountReturn {
    pub fn from_enter_event(
        enter: Fsmount,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FsmountReturn {})
    }
}

impl FsopenReturn {
    pub fn from_enter_event(
        enter: Fsopen,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FsopenReturn {})
    }
}

impl FspickReturn {
    pub fn from_enter_event(
        enter: Fspick,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FspickReturn {})
    }
}

impl FstatReturn {
    pub fn from_enter_event(
        enter: Fstat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FstatReturn {})
    }
}

impl Fstat64Return {
    pub fn from_enter_event(
        enter: Fstat64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Fstat64Return {})
    }
}

impl Fstatat64Return {
    pub fn from_enter_event(
        enter: Fstatat64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Fstatat64Return {})
    }
}

impl FstatfsReturn {
    pub fn from_enter_event(
        enter: Fstatfs,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FstatfsReturn {})
    }
}

impl Fstatfs64Return {
    pub fn from_enter_event(
        enter: Fstatfs64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Fstatfs64Return {})
    }
}

impl FsyncReturn {
    pub fn from_enter_event(
        enter: Fsync,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FsyncReturn {})
    }
}

impl FtruncateReturn {
    pub fn from_enter_event(
        enter: Ftruncate,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FtruncateReturn {})
    }
}

impl Ftruncate64Return {
    pub fn from_enter_event(
        enter: Ftruncate64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Ftruncate64Return {})
    }
}

impl FutexReturn {
    pub fn from_enter_event(
        enter: Futex,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FutexReturn {})
    }
}

impl FutexTime32Return {
    pub fn from_enter_event(
        enter: FutexTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FutexTime32Return {})
    }
}

impl FutimesatReturn {
    pub fn from_enter_event(
        enter: Futimesat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FutimesatReturn {})
    }
}

impl FutimesatTime32Return {
    pub fn from_enter_event(
        enter: FutimesatTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(FutimesatTime32Return {})
    }
}

impl GetMempolicyReturn {
    pub fn from_enter_event(
        enter: GetMempolicy,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetMempolicyReturn {})
    }
}

impl GetRobustListReturn {
    pub fn from_enter_event(
        enter: GetRobustList,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetRobustListReturn {})
    }
}

impl GetThreadAreaReturn {
    pub fn from_enter_event(
        enter: GetThreadArea,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetThreadAreaReturn {})
    }
}

impl GetcpuReturn {
    pub fn from_enter_event(
        enter: Getcpu,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetcpuReturn {})
    }
}

impl GetcwdReturn {
    pub fn from_enter_event(
        enter: Getcwd,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetcwdReturn {})
    }
}

impl GetdentsReturn {
    pub fn from_enter_event(
        enter: Getdents,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetdentsReturn {})
    }
}

impl Getdents64Return {
    pub fn from_enter_event(
        enter: Getdents64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Getdents64Return {})
    }
}

impl GetdomainnameReturn {
    pub fn from_enter_event(
        enter: Getdomainname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetdomainnameReturn {})
    }
}

impl GetdtablesizeReturn {
    pub fn from_enter_event(
        enter: Getdtablesize,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetdtablesizeReturn {})
    }
}

impl GetegidReturn {
    pub fn from_enter_event(
        enter: Getegid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetegidReturn {})
    }
}

impl Getegid16Return {
    pub fn from_enter_event(
        enter: Getegid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Getegid16Return {})
    }
}

impl GeteuidReturn {
    pub fn from_enter_event(
        enter: Geteuid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GeteuidReturn {})
    }
}

impl Geteuid16Return {
    pub fn from_enter_event(
        enter: Geteuid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Geteuid16Return {})
    }
}

impl GetgidReturn {
    pub fn from_enter_event(
        enter: Getgid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetgidReturn {})
    }
}

impl Getgid16Return {
    pub fn from_enter_event(
        enter: Getgid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Getgid16Return {})
    }
}

impl GetgroupsReturn {
    pub fn from_enter_event(
        enter: Getgroups,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetgroupsReturn {})
    }
}

impl Getgroups16Return {
    pub fn from_enter_event(
        enter: Getgroups16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Getgroups16Return {})
    }
}

impl GethostnameReturn {
    pub fn from_enter_event(
        enter: Gethostname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GethostnameReturn {})
    }
}

impl GetitimerReturn {
    pub fn from_enter_event(
        enter: Getitimer,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetitimerReturn {})
    }
}

impl GetpagesizeReturn {
    pub fn from_enter_event(
        enter: Getpagesize,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetpagesizeReturn {})
    }
}

impl GetpeernameReturn {
    pub fn from_enter_event(
        enter: Getpeername,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetpeernameReturn {})
    }
}

impl GetpgidReturn {
    pub fn from_enter_event(
        enter: Getpgid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetpgidReturn {})
    }
}

impl GetpgrpReturn {
    pub fn from_enter_event(
        enter: Getpgrp,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetpgrpReturn {})
    }
}

impl GetpidReturn {
    pub fn from_enter_event(
        enter: Getpid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetpidReturn {})
    }
}

impl GetppidReturn {
    pub fn from_enter_event(
        enter: Getppid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetppidReturn {})
    }
}

impl GetpriorityReturn {
    pub fn from_enter_event(
        enter: Getpriority,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetpriorityReturn {})
    }
}

impl GetrandomReturn {
    pub fn from_enter_event(
        enter: Getrandom,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetrandomReturn {})
    }
}

impl GetresgidReturn {
    pub fn from_enter_event(
        enter: Getresgid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetresgidReturn {})
    }
}

impl Getresgid16Return {
    pub fn from_enter_event(
        enter: Getresgid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Getresgid16Return {})
    }
}

impl GetresuidReturn {
    pub fn from_enter_event(
        enter: Getresuid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetresuidReturn {})
    }
}

impl Getresuid16Return {
    pub fn from_enter_event(
        enter: Getresuid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Getresuid16Return {})
    }
}

impl GetrlimitReturn {
    pub fn from_enter_event(
        enter: Getrlimit,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetrlimitReturn {})
    }
}

impl GetrusageReturn {
    pub fn from_enter_event(
        enter: Getrusage,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetrusageReturn {})
    }
}

impl GetsidReturn {
    pub fn from_enter_event(
        enter: Getsid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetsidReturn {})
    }
}

impl GetsocknameReturn {
    pub fn from_enter_event(
        enter: Getsockname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetsocknameReturn {})
    }
}

impl GetsockoptReturn {
    pub fn from_enter_event(
        enter: Getsockopt,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetsockoptReturn {})
    }
}

impl GettidReturn {
    pub fn from_enter_event(
        enter: Gettid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GettidReturn {})
    }
}

impl GettimeofdayReturn {
    pub fn from_enter_event(
        enter: Gettimeofday,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GettimeofdayReturn {})
    }
}

impl GetuidReturn {
    pub fn from_enter_event(
        enter: Getuid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetuidReturn {})
    }
}

impl Getuid16Return {
    pub fn from_enter_event(
        enter: Getuid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Getuid16Return {})
    }
}

impl GetxattrReturn {
    pub fn from_enter_event(
        enter: Getxattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetxattrReturn {})
    }
}

impl GetxgidReturn {
    pub fn from_enter_event(
        enter: Getxgid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetxgidReturn {})
    }
}

impl GetxpidReturn {
    pub fn from_enter_event(
        enter: Getxpid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetxpidReturn {})
    }
}

impl GetxuidReturn {
    pub fn from_enter_event(
        enter: Getxuid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(GetxuidReturn {})
    }
}

impl InitModuleReturn {
    pub fn from_enter_event(
        enter: InitModule,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(InitModuleReturn {})
    }
}

impl InotifyAddWatchReturn {
    pub fn from_enter_event(
        enter: InotifyAddWatch,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(InotifyAddWatchReturn {})
    }
}

impl InotifyInitReturn {
    pub fn from_enter_event(
        enter: InotifyInit,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(InotifyInitReturn {})
    }
}

impl InotifyInit1Return {
    pub fn from_enter_event(
        enter: InotifyInit1,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(InotifyInit1Return {})
    }
}

impl InotifyRmWatchReturn {
    pub fn from_enter_event(
        enter: InotifyRmWatch,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(InotifyRmWatchReturn {})
    }
}

impl IoCancelReturn {
    pub fn from_enter_event(
        enter: IoCancel,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoCancelReturn {})
    }
}

impl IoDestroyReturn {
    pub fn from_enter_event(
        enter: IoDestroy,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoDestroyReturn {})
    }
}

impl IoGeteventsReturn {
    pub fn from_enter_event(
        enter: IoGetevents,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoGeteventsReturn {})
    }
}

impl IoGeteventsTime32Return {
    pub fn from_enter_event(
        enter: IoGeteventsTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoGeteventsTime32Return {})
    }
}

impl IoPgeteventsReturn {
    pub fn from_enter_event(
        enter: IoPgetevents,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoPgeteventsReturn {})
    }
}

impl IoPgeteventsTime32Return {
    pub fn from_enter_event(
        enter: IoPgeteventsTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoPgeteventsTime32Return {})
    }
}

impl IoSetupReturn {
    pub fn from_enter_event(
        enter: IoSetup,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoSetupReturn {})
    }
}

impl IoSubmitReturn {
    pub fn from_enter_event(
        enter: IoSubmit,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoSubmitReturn {})
    }
}

impl IoUringEnterReturn {
    pub fn from_enter_event(
        enter: IoUringEnter,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoUringEnterReturn {})
    }
}

impl IoUringRegisterReturn {
    pub fn from_enter_event(
        enter: IoUringRegister,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoUringRegisterReturn {})
    }
}

impl IoUringSetupReturn {
    pub fn from_enter_event(
        enter: IoUringSetup,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoUringSetupReturn {})
    }
}

impl IoctlReturn {
    pub fn from_enter_event(
        enter: Ioctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoctlReturn {})
    }
}

impl IopermReturn {
    pub fn from_enter_event(
        enter: Ioperm,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IopermReturn {})
    }
}

impl IoplReturn {
    pub fn from_enter_event(
        enter: Iopl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoplReturn {})
    }
}

impl IoprioGetReturn {
    pub fn from_enter_event(
        enter: IoprioGet,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoprioGetReturn {})
    }
}

impl IoprioSetReturn {
    pub fn from_enter_event(
        enter: IoprioSet,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IoprioSetReturn {})
    }
}

impl IpcReturn {
    pub fn from_enter_event(
        enter: Ipc,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(IpcReturn {})
    }
}

impl KcmpReturn {
    pub fn from_enter_event(
        enter: Kcmp,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(KcmpReturn {})
    }
}

impl KernFeaturesReturn {
    pub fn from_enter_event(
        enter: KernFeatures,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(KernFeaturesReturn {})
    }
}

impl KexecFileLoadReturn {
    pub fn from_enter_event(
        enter: KexecFileLoad,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(KexecFileLoadReturn {})
    }
}

impl KexecLoadReturn {
    pub fn from_enter_event(
        enter: KexecLoad,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(KexecLoadReturn {})
    }
}

impl KeyctlReturn {
    pub fn from_enter_event(
        enter: Keyctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(KeyctlReturn {})
    }
}

impl KillReturn {
    pub fn from_enter_event(
        enter: Kill,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(KillReturn {})
    }
}

impl LchownReturn {
    pub fn from_enter_event(
        enter: Lchown,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LchownReturn {})
    }
}

impl Lchown16Return {
    pub fn from_enter_event(
        enter: Lchown16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Lchown16Return {})
    }
}

impl LgetxattrReturn {
    pub fn from_enter_event(
        enter: Lgetxattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LgetxattrReturn {})
    }
}

impl LinkReturn {
    pub fn from_enter_event(
        enter: Link,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LinkReturn {})
    }
}

impl LinkatReturn {
    pub fn from_enter_event(
        enter: Linkat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LinkatReturn {})
    }
}

impl ListenReturn {
    pub fn from_enter_event(
        enter: Listen,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ListenReturn {})
    }
}

impl ListxattrReturn {
    pub fn from_enter_event(
        enter: Listxattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ListxattrReturn {})
    }
}

impl LlistxattrReturn {
    pub fn from_enter_event(
        enter: Llistxattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LlistxattrReturn {})
    }
}

impl LlseekReturn {
    pub fn from_enter_event(
        enter: Llseek,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LlseekReturn {})
    }
}

impl LookupDcookieReturn {
    pub fn from_enter_event(
        enter: LookupDcookie,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LookupDcookieReturn {})
    }
}

impl LremovexattrReturn {
    pub fn from_enter_event(
        enter: Lremovexattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LremovexattrReturn {})
    }
}

impl LseekReturn {
    pub fn from_enter_event(
        enter: Lseek,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LseekReturn {})
    }
}

impl LsetxattrReturn {
    pub fn from_enter_event(
        enter: Lsetxattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LsetxattrReturn {})
    }
}

impl LstatReturn {
    pub fn from_enter_event(
        enter: Lstat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(LstatReturn {})
    }
}

impl Lstat64Return {
    pub fn from_enter_event(
        enter: Lstat64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Lstat64Return {})
    }
}

impl MadviseReturn {
    pub fn from_enter_event(
        enter: Madvise,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MadviseReturn {})
    }
}

impl MbindReturn {
    pub fn from_enter_event(
        enter: Mbind,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MbindReturn {})
    }
}

impl MembarrierReturn {
    pub fn from_enter_event(
        enter: Membarrier,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MembarrierReturn {})
    }
}

impl MemfdCreateReturn {
    pub fn from_enter_event(
        enter: MemfdCreate,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MemfdCreateReturn {})
    }
}

impl MemoryOrderingReturn {
    pub fn from_enter_event(
        enter: MemoryOrdering,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MemoryOrderingReturn {})
    }
}

impl MigratePagesReturn {
    pub fn from_enter_event(
        enter: MigratePages,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MigratePagesReturn {})
    }
}

impl MincoreReturn {
    pub fn from_enter_event(
        enter: Mincore,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MincoreReturn {})
    }
}

impl MipsMmapReturn {
    pub fn from_enter_event(
        enter: MipsMmap,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MipsMmapReturn {})
    }
}

impl MipsMmap2Return {
    pub fn from_enter_event(
        enter: MipsMmap2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MipsMmap2Return {})
    }
}

impl MkdirReturn {
    pub fn from_enter_event(
        enter: Mkdir,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MkdirReturn {})
    }
}

impl MkdiratReturn {
    pub fn from_enter_event(
        enter: Mkdirat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MkdiratReturn {})
    }
}

impl MknodReturn {
    pub fn from_enter_event(
        enter: Mknod,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MknodReturn {})
    }
}

impl MknodatReturn {
    pub fn from_enter_event(
        enter: Mknodat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MknodatReturn {})
    }
}

impl MlockReturn {
    pub fn from_enter_event(
        enter: Mlock,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MlockReturn {})
    }
}

impl Mlock2Return {
    pub fn from_enter_event(
        enter: Mlock2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Mlock2Return {})
    }
}

impl MlockallReturn {
    pub fn from_enter_event(
        enter: Mlockall,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MlockallReturn {})
    }
}

impl MmapReturn {
    pub fn from_enter_event(
        enter: Mmap,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MmapReturn {
            address: retval as *mut c_void,
        })
    }
}

impl Mmap2Return {
    pub fn from_enter_event(
        enter: Mmap2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Mmap2Return {})
    }
}

impl MmapPgoffReturn {
    pub fn from_enter_event(
        enter: MmapPgoff,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MmapPgoffReturn {})
    }
}

impl ModifyLdtReturn {
    pub fn from_enter_event(
        enter: ModifyLdt,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ModifyLdtReturn {})
    }
}

impl MountReturn {
    pub fn from_enter_event(
        enter: Mount,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MountReturn {})
    }
}

impl MoveMountReturn {
    pub fn from_enter_event(
        enter: MoveMount,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MoveMountReturn {})
    }
}

impl MovePagesReturn {
    pub fn from_enter_event(
        enter: MovePages,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MovePagesReturn {})
    }
}

impl MprotectReturn {
    pub fn from_enter_event(
        enter: Mprotect,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MprotectReturn {})
    }
}

impl MqGetsetattrReturn {
    pub fn from_enter_event(
        enter: MqGetsetattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MqGetsetattrReturn {})
    }
}

impl MqNotifyReturn {
    pub fn from_enter_event(
        enter: MqNotify,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MqNotifyReturn {})
    }
}

impl MqOpenReturn {
    pub fn from_enter_event(
        enter: MqOpen,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MqOpenReturn {})
    }
}

impl MqTimedreceiveReturn {
    pub fn from_enter_event(
        enter: MqTimedreceive,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MqTimedreceiveReturn {})
    }
}

impl MqTimedreceiveTime32Return {
    pub fn from_enter_event(
        enter: MqTimedreceiveTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MqTimedreceiveTime32Return {})
    }
}

impl MqTimedsendReturn {
    pub fn from_enter_event(
        enter: MqTimedsend,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MqTimedsendReturn {})
    }
}

impl MqTimedsendTime32Return {
    pub fn from_enter_event(
        enter: MqTimedsendTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MqTimedsendTime32Return {})
    }
}

impl MqUnlinkReturn {
    pub fn from_enter_event(
        enter: MqUnlink,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MqUnlinkReturn {})
    }
}

impl MremapReturn {
    pub fn from_enter_event(
        enter: Mremap,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MremapReturn {})
    }
}

impl MsgctlReturn {
    pub fn from_enter_event(
        enter: Msgctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MsgctlReturn {})
    }
}

impl MsggetReturn {
    pub fn from_enter_event(
        enter: Msgget,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MsggetReturn {})
    }
}

impl MsgrcvReturn {
    pub fn from_enter_event(
        enter: Msgrcv,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MsgrcvReturn {})
    }
}

impl MsgsndReturn {
    pub fn from_enter_event(
        enter: Msgsnd,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MsgsndReturn {})
    }
}

impl MsyncReturn {
    pub fn from_enter_event(
        enter: Msync,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MsyncReturn {})
    }
}

impl MunlockReturn {
    pub fn from_enter_event(
        enter: Munlock,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MunlockReturn {})
    }
}

impl MunlockallReturn {
    pub fn from_enter_event(
        enter: Munlockall,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MunlockallReturn {})
    }
}

impl MunmapReturn {
    pub fn from_enter_event(
        enter: Munmap,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(MunmapReturn {})
    }
}

impl NameToHandleAtReturn {
    pub fn from_enter_event(
        enter: NameToHandleAt,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NameToHandleAtReturn {})
    }
}

impl NanosleepReturn {
    pub fn from_enter_event(
        enter: Nanosleep,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NanosleepReturn {})
    }
}

impl NanosleepTime32Return {
    pub fn from_enter_event(
        enter: NanosleepTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NanosleepTime32Return {})
    }
}

impl NewfstatReturn {
    pub fn from_enter_event(
        enter: Newfstat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NewfstatReturn {})
    }
}

impl NewfstatatReturn {
    pub fn from_enter_event(
        enter: Newfstatat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NewfstatatReturn {})
    }
}

impl NewlstatReturn {
    pub fn from_enter_event(
        enter: Newlstat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NewlstatReturn {})
    }
}

impl NewstatReturn {
    pub fn from_enter_event(
        enter: Newstat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NewstatReturn {})
    }
}

impl NewunameReturn {
    pub fn from_enter_event(
        enter: Newuname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NewunameReturn {})
    }
}

impl NiSyscallReturn {
    pub fn from_enter_event(
        enter: NiSyscall,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NiSyscallReturn {})
    }
}

impl NiceReturn {
    pub fn from_enter_event(
        enter: Nice,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NiceReturn {})
    }
}

impl NisSyscallReturn {
    pub fn from_enter_event(
        enter: NisSyscall,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(NisSyscallReturn {})
    }
}

impl OldAdjtimexReturn {
    pub fn from_enter_event(
        enter: OldAdjtimex,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldAdjtimexReturn {})
    }
}

impl OldGetrlimitReturn {
    pub fn from_enter_event(
        enter: OldGetrlimit,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldGetrlimitReturn {})
    }
}

impl OldMmapReturn {
    pub fn from_enter_event(
        enter: OldMmap,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldMmapReturn {})
    }
}

impl OldMsgctlReturn {
    pub fn from_enter_event(
        enter: OldMsgctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldMsgctlReturn {})
    }
}

impl OldReaddirReturn {
    pub fn from_enter_event(
        enter: OldReaddir,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldReaddirReturn {})
    }
}

impl OldSelectReturn {
    pub fn from_enter_event(
        enter: OldSelect,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldSelectReturn {})
    }
}

impl OldSemctlReturn {
    pub fn from_enter_event(
        enter: OldSemctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldSemctlReturn {})
    }
}

impl OldShmctlReturn {
    pub fn from_enter_event(
        enter: OldShmctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldShmctlReturn {})
    }
}

impl OldumountReturn {
    pub fn from_enter_event(
        enter: Oldumount,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldumountReturn {})
    }
}

impl OldunameReturn {
    pub fn from_enter_event(
        enter: Olduname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OldunameReturn {})
    }
}

impl OpenReturn {
    pub fn from_enter_event(
        enter: Open,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OpenReturn {})
    }
}

impl OpenByHandleAtReturn {
    pub fn from_enter_event(
        enter: OpenByHandleAt,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OpenByHandleAtReturn {})
    }
}

impl OpenTreeReturn {
    pub fn from_enter_event(
        enter: OpenTree,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OpenTreeReturn {})
    }
}

impl OpenatReturn {
    pub fn from_enter_event(
        enter: Openat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OpenatReturn {
            file_descriptor: retval as i32,
        })
    }
}

impl Openat2Return {
    pub fn from_enter_event(
        enter: Openat2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Openat2Return {})
    }
}

impl OsfBrkReturn {
    pub fn from_enter_event(
        enter: OsfBrk,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfBrkReturn {})
    }
}

impl OsfFstatReturn {
    pub fn from_enter_event(
        enter: OsfFstat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfFstatReturn {})
    }
}

impl OsfFstatfsReturn {
    pub fn from_enter_event(
        enter: OsfFstatfs,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfFstatfsReturn {})
    }
}

impl OsfFstatfs64Return {
    pub fn from_enter_event(
        enter: OsfFstatfs64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfFstatfs64Return {})
    }
}

impl OsfGetdirentriesReturn {
    pub fn from_enter_event(
        enter: OsfGetdirentries,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfGetdirentriesReturn {})
    }
}

impl OsfGetdomainnameReturn {
    pub fn from_enter_event(
        enter: OsfGetdomainname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfGetdomainnameReturn {})
    }
}

impl OsfGetpriorityReturn {
    pub fn from_enter_event(
        enter: OsfGetpriority,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfGetpriorityReturn {})
    }
}

impl OsfGetrusageReturn {
    pub fn from_enter_event(
        enter: OsfGetrusage,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfGetrusageReturn {})
    }
}

impl OsfGetsysinfoReturn {
    pub fn from_enter_event(
        enter: OsfGetsysinfo,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfGetsysinfoReturn {})
    }
}

impl OsfGettimeofdayReturn {
    pub fn from_enter_event(
        enter: OsfGettimeofday,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfGettimeofdayReturn {})
    }
}

impl OsfLstatReturn {
    pub fn from_enter_event(
        enter: OsfLstat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfLstatReturn {})
    }
}

impl OsfMmapReturn {
    pub fn from_enter_event(
        enter: OsfMmap,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfMmapReturn {})
    }
}

impl OsfMountReturn {
    pub fn from_enter_event(
        enter: OsfMount,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfMountReturn {})
    }
}

impl OsfProplistSyscallReturn {
    pub fn from_enter_event(
        enter: OsfProplistSyscall,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfProplistSyscallReturn {})
    }
}

impl OsfReadvReturn {
    pub fn from_enter_event(
        enter: OsfReadv,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfReadvReturn {})
    }
}

impl OsfSelectReturn {
    pub fn from_enter_event(
        enter: OsfSelect,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfSelectReturn {})
    }
}

impl OsfSetProgramAttributesReturn {
    pub fn from_enter_event(
        enter: OsfSetProgramAttributes,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfSetProgramAttributesReturn {})
    }
}

impl OsfSetsysinfoReturn {
    pub fn from_enter_event(
        enter: OsfSetsysinfo,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfSetsysinfoReturn {})
    }
}

impl OsfSettimeofdayReturn {
    pub fn from_enter_event(
        enter: OsfSettimeofday,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfSettimeofdayReturn {})
    }
}

impl OsfSigactionReturn {
    pub fn from_enter_event(
        enter: OsfSigaction,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfSigactionReturn {})
    }
}

impl OsfSigprocmaskReturn {
    pub fn from_enter_event(
        enter: OsfSigprocmask,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfSigprocmaskReturn {})
    }
}

impl OsfSigstackReturn {
    pub fn from_enter_event(
        enter: OsfSigstack,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfSigstackReturn {})
    }
}

impl OsfStatReturn {
    pub fn from_enter_event(
        enter: OsfStat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfStatReturn {})
    }
}

impl OsfStatfsReturn {
    pub fn from_enter_event(
        enter: OsfStatfs,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfStatfsReturn {})
    }
}

impl OsfStatfs64Return {
    pub fn from_enter_event(
        enter: OsfStatfs64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfStatfs64Return {})
    }
}

impl OsfSysinfoReturn {
    pub fn from_enter_event(
        enter: OsfSysinfo,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfSysinfoReturn {})
    }
}

impl OsfUsleepThreadReturn {
    pub fn from_enter_event(
        enter: OsfUsleepThread,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfUsleepThreadReturn {})
    }
}

impl OsfUtimesReturn {
    pub fn from_enter_event(
        enter: OsfUtimes,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfUtimesReturn {})
    }
}

impl OsfUtsnameReturn {
    pub fn from_enter_event(
        enter: OsfUtsname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfUtsnameReturn {})
    }
}

impl OsfWait4Return {
    pub fn from_enter_event(
        enter: OsfWait4,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfWait4Return {})
    }
}

impl OsfWritevReturn {
    pub fn from_enter_event(
        enter: OsfWritev,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(OsfWritevReturn {})
    }
}

impl PauseReturn {
    pub fn from_enter_event(
        enter: Pause,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PauseReturn {})
    }
}

impl PciconfigIobaseReturn {
    pub fn from_enter_event(
        enter: PciconfigIobase,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PciconfigIobaseReturn {})
    }
}

impl PciconfigReadReturn {
    pub fn from_enter_event(
        enter: PciconfigRead,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PciconfigReadReturn {})
    }
}

impl PciconfigWriteReturn {
    pub fn from_enter_event(
        enter: PciconfigWrite,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PciconfigWriteReturn {})
    }
}

impl PerfEventOpenReturn {
    pub fn from_enter_event(
        enter: PerfEventOpen,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PerfEventOpenReturn {})
    }
}

impl PersonalityReturn {
    pub fn from_enter_event(
        enter: Personality,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PersonalityReturn {})
    }
}

impl PidfdGetfdReturn {
    pub fn from_enter_event(
        enter: PidfdGetfd,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PidfdGetfdReturn {})
    }
}

impl PidfdOpenReturn {
    pub fn from_enter_event(
        enter: PidfdOpen,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PidfdOpenReturn {})
    }
}

impl PidfdSendSignalReturn {
    pub fn from_enter_event(
        enter: PidfdSendSignal,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PidfdSendSignalReturn {})
    }
}

impl PipeReturn {
    pub fn from_enter_event(
        enter: Pipe,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PipeReturn {})
    }
}

impl Pipe2Return {
    pub fn from_enter_event(
        enter: Pipe2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Pipe2Return {})
    }
}

impl PivotRootReturn {
    pub fn from_enter_event(
        enter: PivotRoot,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PivotRootReturn {})
    }
}

impl PkeyAllocReturn {
    pub fn from_enter_event(
        enter: PkeyAlloc,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PkeyAllocReturn {})
    }
}

impl PkeyFreeReturn {
    pub fn from_enter_event(
        enter: PkeyFree,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PkeyFreeReturn {})
    }
}

impl PkeyMprotectReturn {
    pub fn from_enter_event(
        enter: PkeyMprotect,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PkeyMprotectReturn {})
    }
}

impl PollReturn {
    pub fn from_enter_event(
        enter: Poll,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PollReturn {})
    }
}

impl PpollReturn {
    pub fn from_enter_event(
        enter: Ppoll,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PpollReturn {})
    }
}

impl PpollTime32Return {
    pub fn from_enter_event(
        enter: PpollTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PpollTime32Return {})
    }
}

impl PrctlReturn {
    pub fn from_enter_event(
        enter: Prctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PrctlReturn {})
    }
}

impl Pread64Return {
    pub fn from_enter_event(
        enter: Pread64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Pread64Return {})
    }
}

impl PreadvReturn {
    pub fn from_enter_event(
        enter: Preadv,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PreadvReturn {})
    }
}

impl Preadv2Return {
    pub fn from_enter_event(
        enter: Preadv2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Preadv2Return {})
    }
}

impl Prlimit64Return {
    pub fn from_enter_event(
        enter: Prlimit64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Prlimit64Return {})
    }
}

impl ProcessVmReadvReturn {
    pub fn from_enter_event(
        enter: ProcessVmReadv,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ProcessVmReadvReturn {})
    }
}

impl ProcessVmWritevReturn {
    pub fn from_enter_event(
        enter: ProcessVmWritev,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ProcessVmWritevReturn {})
    }
}

impl Pselect6Return {
    pub fn from_enter_event(
        enter: Pselect6,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Pselect6Return {})
    }
}

impl Pselect6Time32Return {
    pub fn from_enter_event(
        enter: Pselect6Time32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Pselect6Time32Return {})
    }
}

impl PtraceReturn {
    pub fn from_enter_event(
        enter: Ptrace,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PtraceReturn {})
    }
}

impl Pwrite64Return {
    pub fn from_enter_event(
        enter: Pwrite64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Pwrite64Return {})
    }
}

impl PwritevReturn {
    pub fn from_enter_event(
        enter: Pwritev,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(PwritevReturn {})
    }
}

impl Pwritev2Return {
    pub fn from_enter_event(
        enter: Pwritev2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Pwritev2Return {})
    }
}

impl QuotactlReturn {
    pub fn from_enter_event(
        enter: Quotactl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(QuotactlReturn {})
    }
}

impl ReadReturn {
    pub fn from_enter_event(
        enter: Read,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ReadReturn {})
    }
}

impl ReadaheadReturn {
    pub fn from_enter_event(
        enter: Readahead,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ReadaheadReturn {})
    }
}

impl ReadlinkReturn {
    pub fn from_enter_event(
        enter: Readlink,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ReadlinkReturn {})
    }
}

impl ReadlinkatReturn {
    pub fn from_enter_event(
        enter: Readlinkat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ReadlinkatReturn {})
    }
}

impl ReadvReturn {
    pub fn from_enter_event(
        enter: Readv,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ReadvReturn {})
    }
}

impl RebootReturn {
    pub fn from_enter_event(
        enter: Reboot,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RebootReturn {})
    }
}

impl RecvReturn {
    pub fn from_enter_event(
        enter: Recv,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RecvReturn {})
    }
}

impl RecvfromReturn {
    pub fn from_enter_event(
        enter: Recvfrom,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RecvfromReturn {})
    }
}

impl RecvmmsgReturn {
    pub fn from_enter_event(
        enter: Recvmmsg,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RecvmmsgReturn {})
    }
}

impl RecvmmsgTime32Return {
    pub fn from_enter_event(
        enter: RecvmmsgTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RecvmmsgTime32Return {})
    }
}

impl RecvmsgReturn {
    pub fn from_enter_event(
        enter: Recvmsg,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RecvmsgReturn {})
    }
}

impl RemapFilePagesReturn {
    pub fn from_enter_event(
        enter: RemapFilePages,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RemapFilePagesReturn {})
    }
}

impl RemovexattrReturn {
    pub fn from_enter_event(
        enter: Removexattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RemovexattrReturn {})
    }
}

impl RenameReturn {
    pub fn from_enter_event(
        enter: Rename,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RenameReturn {})
    }
}

impl RenameatReturn {
    pub fn from_enter_event(
        enter: Renameat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RenameatReturn {})
    }
}

impl Renameat2Return {
    pub fn from_enter_event(
        enter: Renameat2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Renameat2Return {})
    }
}

impl RequestKeyReturn {
    pub fn from_enter_event(
        enter: RequestKey,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RequestKeyReturn {})
    }
}

impl RestartSyscallReturn {
    pub fn from_enter_event(
        enter: RestartSyscall,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RestartSyscallReturn {})
    }
}

impl RiscvFlushIcacheReturn {
    pub fn from_enter_event(
        enter: RiscvFlushIcache,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RiscvFlushIcacheReturn {})
    }
}

impl RmdirReturn {
    pub fn from_enter_event(
        enter: Rmdir,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RmdirReturn {})
    }
}

impl RseqReturn {
    pub fn from_enter_event(
        enter: Rseq,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RseqReturn {})
    }
}

impl RtSigactionReturn {
    pub fn from_enter_event(
        enter: RtSigaction,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtSigactionReturn {})
    }
}

impl RtSigpendingReturn {
    pub fn from_enter_event(
        enter: RtSigpending,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtSigpendingReturn {})
    }
}

impl RtSigprocmaskReturn {
    pub fn from_enter_event(
        enter: RtSigprocmask,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtSigprocmaskReturn {})
    }
}

impl RtSigqueueinfoReturn {
    pub fn from_enter_event(
        enter: RtSigqueueinfo,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtSigqueueinfoReturn {})
    }
}

impl RtSigreturnReturn {
    pub fn from_enter_event(
        enter: RtSigreturn,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtSigreturnReturn {})
    }
}

impl RtSigsuspendReturn {
    pub fn from_enter_event(
        enter: RtSigsuspend,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtSigsuspendReturn {})
    }
}

impl RtSigtimedwaitReturn {
    pub fn from_enter_event(
        enter: RtSigtimedwait,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtSigtimedwaitReturn {})
    }
}

impl RtSigtimedwaitTime32Return {
    pub fn from_enter_event(
        enter: RtSigtimedwaitTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtSigtimedwaitTime32Return {})
    }
}

impl RtTgsigqueueinfoReturn {
    pub fn from_enter_event(
        enter: RtTgsigqueueinfo,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtTgsigqueueinfoReturn {})
    }
}

impl RtasReturn {
    pub fn from_enter_event(
        enter: Rtas,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(RtasReturn {})
    }
}

impl S390GuardedStorageReturn {
    pub fn from_enter_event(
        enter: S390GuardedStorage,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(S390GuardedStorageReturn {})
    }
}

impl S390IpcReturn {
    pub fn from_enter_event(
        enter: S390Ipc,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(S390IpcReturn {})
    }
}

impl S390PciMmioReadReturn {
    pub fn from_enter_event(
        enter: S390PciMmioRead,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(S390PciMmioReadReturn {})
    }
}

impl S390PciMmioWriteReturn {
    pub fn from_enter_event(
        enter: S390PciMmioWrite,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(S390PciMmioWriteReturn {})
    }
}

impl S390PersonalityReturn {
    pub fn from_enter_event(
        enter: S390Personality,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(S390PersonalityReturn {})
    }
}

impl S390RuntimeInstrReturn {
    pub fn from_enter_event(
        enter: S390RuntimeInstr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(S390RuntimeInstrReturn {})
    }
}

impl S390SthyiReturn {
    pub fn from_enter_event(
        enter: S390Sthyi,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(S390SthyiReturn {})
    }
}

impl SchedGetPriorityMaxReturn {
    pub fn from_enter_event(
        enter: SchedGetPriorityMax,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedGetPriorityMaxReturn {})
    }
}

impl SchedGetPriorityMinReturn {
    pub fn from_enter_event(
        enter: SchedGetPriorityMin,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedGetPriorityMinReturn {})
    }
}

impl SchedGetaffinityReturn {
    pub fn from_enter_event(
        enter: SchedGetaffinity,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedGetaffinityReturn {})
    }
}

impl SchedGetattrReturn {
    pub fn from_enter_event(
        enter: SchedGetattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedGetattrReturn {})
    }
}

impl SchedGetparamReturn {
    pub fn from_enter_event(
        enter: SchedGetparam,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedGetparamReturn {})
    }
}

impl SchedGetschedulerReturn {
    pub fn from_enter_event(
        enter: SchedGetscheduler,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedGetschedulerReturn {})
    }
}

impl SchedRrGetIntervalReturn {
    pub fn from_enter_event(
        enter: SchedRrGetInterval,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedRrGetIntervalReturn {})
    }
}

impl SchedRrGetIntervalTime32Return {
    pub fn from_enter_event(
        enter: SchedRrGetIntervalTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedRrGetIntervalTime32Return {})
    }
}

impl SchedSetaffinityReturn {
    pub fn from_enter_event(
        enter: SchedSetaffinity,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedSetaffinityReturn {})
    }
}

impl SchedSetattrReturn {
    pub fn from_enter_event(
        enter: SchedSetattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedSetattrReturn {})
    }
}

impl SchedSetparamReturn {
    pub fn from_enter_event(
        enter: SchedSetparam,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedSetparamReturn {})
    }
}

impl SchedSetschedulerReturn {
    pub fn from_enter_event(
        enter: SchedSetscheduler,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedSetschedulerReturn {})
    }
}

impl SchedYieldReturn {
    pub fn from_enter_event(
        enter: SchedYield,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SchedYieldReturn {})
    }
}

impl SeccompReturn {
    pub fn from_enter_event(
        enter: Seccomp,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SeccompReturn {})
    }
}

impl SelectReturn {
    pub fn from_enter_event(
        enter: Select,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SelectReturn {})
    }
}

impl SemctlReturn {
    pub fn from_enter_event(
        enter: Semctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SemctlReturn {})
    }
}

impl SemgetReturn {
    pub fn from_enter_event(
        enter: Semget,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SemgetReturn {})
    }
}

impl SemopReturn {
    pub fn from_enter_event(
        enter: Semop,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SemopReturn {})
    }
}

impl SemtimedopReturn {
    pub fn from_enter_event(
        enter: Semtimedop,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SemtimedopReturn {})
    }
}

impl SemtimedopTime32Return {
    pub fn from_enter_event(
        enter: SemtimedopTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SemtimedopTime32Return {})
    }
}

impl SendReturn {
    pub fn from_enter_event(
        enter: Send,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SendReturn {})
    }
}

impl SendfileReturn {
    pub fn from_enter_event(
        enter: Sendfile,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SendfileReturn {})
    }
}

impl Sendfile64Return {
    pub fn from_enter_event(
        enter: Sendfile64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Sendfile64Return {})
    }
}

impl SendmmsgReturn {
    pub fn from_enter_event(
        enter: Sendmmsg,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SendmmsgReturn {})
    }
}

impl SendmsgReturn {
    pub fn from_enter_event(
        enter: Sendmsg,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SendmsgReturn {})
    }
}

impl SendtoReturn {
    pub fn from_enter_event(
        enter: Sendto,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SendtoReturn {})
    }
}

impl SetMempolicyReturn {
    pub fn from_enter_event(
        enter: SetMempolicy,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetMempolicyReturn {})
    }
}

impl SetRobustListReturn {
    pub fn from_enter_event(
        enter: SetRobustList,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetRobustListReturn {})
    }
}

impl SetThreadAreaReturn {
    pub fn from_enter_event(
        enter: SetThreadArea,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetThreadAreaReturn {})
    }
}

impl SetTidAddressReturn {
    pub fn from_enter_event(
        enter: SetTidAddress,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetTidAddressReturn {})
    }
}

impl SetdomainnameReturn {
    pub fn from_enter_event(
        enter: Setdomainname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetdomainnameReturn {})
    }
}

impl SetfsgidReturn {
    pub fn from_enter_event(
        enter: Setfsgid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetfsgidReturn {})
    }
}

impl Setfsgid16Return {
    pub fn from_enter_event(
        enter: Setfsgid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Setfsgid16Return {})
    }
}

impl SetfsuidReturn {
    pub fn from_enter_event(
        enter: Setfsuid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetfsuidReturn {})
    }
}

impl Setfsuid16Return {
    pub fn from_enter_event(
        enter: Setfsuid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Setfsuid16Return {})
    }
}

impl SetgidReturn {
    pub fn from_enter_event(
        enter: Setgid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetgidReturn {})
    }
}

impl Setgid16Return {
    pub fn from_enter_event(
        enter: Setgid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Setgid16Return {})
    }
}

impl SetgroupsReturn {
    pub fn from_enter_event(
        enter: Setgroups,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetgroupsReturn {})
    }
}

impl Setgroups16Return {
    pub fn from_enter_event(
        enter: Setgroups16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Setgroups16Return {})
    }
}

impl SethaeReturn {
    pub fn from_enter_event(
        enter: Sethae,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SethaeReturn {})
    }
}

impl SethostnameReturn {
    pub fn from_enter_event(
        enter: Sethostname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SethostnameReturn {})
    }
}

impl SetitimerReturn {
    pub fn from_enter_event(
        enter: Setitimer,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetitimerReturn {})
    }
}

impl SetnsReturn {
    pub fn from_enter_event(
        enter: Setns,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetnsReturn {})
    }
}

impl SetpgidReturn {
    pub fn from_enter_event(
        enter: Setpgid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetpgidReturn {})
    }
}

impl SetpriorityReturn {
    pub fn from_enter_event(
        enter: Setpriority,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetpriorityReturn {})
    }
}

impl SetregidReturn {
    pub fn from_enter_event(
        enter: Setregid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetregidReturn {})
    }
}

impl Setregid16Return {
    pub fn from_enter_event(
        enter: Setregid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Setregid16Return {})
    }
}

impl SetresgidReturn {
    pub fn from_enter_event(
        enter: Setresgid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetresgidReturn {})
    }
}

impl Setresgid16Return {
    pub fn from_enter_event(
        enter: Setresgid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Setresgid16Return {})
    }
}

impl SetresuidReturn {
    pub fn from_enter_event(
        enter: Setresuid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetresuidReturn {})
    }
}

impl Setresuid16Return {
    pub fn from_enter_event(
        enter: Setresuid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Setresuid16Return {})
    }
}

impl SetreuidReturn {
    pub fn from_enter_event(
        enter: Setreuid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetreuidReturn {})
    }
}

impl Setreuid16Return {
    pub fn from_enter_event(
        enter: Setreuid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Setreuid16Return {})
    }
}

impl SetrlimitReturn {
    pub fn from_enter_event(
        enter: Setrlimit,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetrlimitReturn {})
    }
}

impl SetsidReturn {
    pub fn from_enter_event(
        enter: Setsid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetsidReturn {})
    }
}

impl SetsockoptReturn {
    pub fn from_enter_event(
        enter: Setsockopt,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetsockoptReturn {})
    }
}

impl SettimeofdayReturn {
    pub fn from_enter_event(
        enter: Settimeofday,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SettimeofdayReturn {})
    }
}

impl SetuidReturn {
    pub fn from_enter_event(
        enter: Setuid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetuidReturn {})
    }
}

impl Setuid16Return {
    pub fn from_enter_event(
        enter: Setuid16,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Setuid16Return {})
    }
}

impl SetxattrReturn {
    pub fn from_enter_event(
        enter: Setxattr,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SetxattrReturn {})
    }
}

impl SgetmaskReturn {
    pub fn from_enter_event(
        enter: Sgetmask,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SgetmaskReturn {})
    }
}

impl ShmatReturn {
    pub fn from_enter_event(
        enter: Shmat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ShmatReturn {})
    }
}

impl ShmctlReturn {
    pub fn from_enter_event(
        enter: Shmctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ShmctlReturn {})
    }
}

impl ShmdtReturn {
    pub fn from_enter_event(
        enter: Shmdt,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ShmdtReturn {})
    }
}

impl ShmgetReturn {
    pub fn from_enter_event(
        enter: Shmget,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ShmgetReturn {})
    }
}

impl ShutdownReturn {
    pub fn from_enter_event(
        enter: Shutdown,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(ShutdownReturn {})
    }
}

impl SigactionReturn {
    pub fn from_enter_event(
        enter: Sigaction,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SigactionReturn {})
    }
}

impl SigaltstackReturn {
    pub fn from_enter_event(
        enter: Sigaltstack,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SigaltstackReturn {})
    }
}

impl SignalReturn {
    pub fn from_enter_event(
        enter: Signal,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SignalReturn {})
    }
}

impl SignalfdReturn {
    pub fn from_enter_event(
        enter: Signalfd,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SignalfdReturn {})
    }
}

impl Signalfd4Return {
    pub fn from_enter_event(
        enter: Signalfd4,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Signalfd4Return {})
    }
}

impl SigpendingReturn {
    pub fn from_enter_event(
        enter: Sigpending,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SigpendingReturn {})
    }
}

impl SigprocmaskReturn {
    pub fn from_enter_event(
        enter: Sigprocmask,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SigprocmaskReturn {})
    }
}

impl SigreturnReturn {
    pub fn from_enter_event(
        enter: Sigreturn,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SigreturnReturn {})
    }
}

impl SigsuspendReturn {
    pub fn from_enter_event(
        enter: Sigsuspend,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SigsuspendReturn {})
    }
}

impl SocketReturn {
    pub fn from_enter_event(
        enter: Socket,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SocketReturn {})
    }
}

impl SocketcallReturn {
    pub fn from_enter_event(
        enter: Socketcall,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SocketcallReturn {})
    }
}

impl SocketpairReturn {
    pub fn from_enter_event(
        enter: Socketpair,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SocketpairReturn {})
    }
}

impl Sparc64PersonalityReturn {
    pub fn from_enter_event(
        enter: Sparc64Personality,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Sparc64PersonalityReturn {})
    }
}

impl SparcAdjtimexReturn {
    pub fn from_enter_event(
        enter: SparcAdjtimex,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SparcAdjtimexReturn {})
    }
}

impl SparcClockAdjtimeReturn {
    pub fn from_enter_event(
        enter: SparcClockAdjtime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SparcClockAdjtimeReturn {})
    }
}

impl SparcIpcReturn {
    pub fn from_enter_event(
        enter: SparcIpc,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SparcIpcReturn {})
    }
}

impl SparcPipeReturn {
    pub fn from_enter_event(
        enter: SparcPipe,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SparcPipeReturn {})
    }
}

impl SparcRemapFilePagesReturn {
    pub fn from_enter_event(
        enter: SparcRemapFilePages,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SparcRemapFilePagesReturn {})
    }
}

impl SparcSigactionReturn {
    pub fn from_enter_event(
        enter: SparcSigaction,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SparcSigactionReturn {})
    }
}

impl SpliceReturn {
    pub fn from_enter_event(
        enter: Splice,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SpliceReturn {})
    }
}

impl SpuCreateReturn {
    pub fn from_enter_event(
        enter: SpuCreate,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SpuCreateReturn {})
    }
}

impl SpuRunReturn {
    pub fn from_enter_event(
        enter: SpuRun,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SpuRunReturn {})
    }
}

impl SsetmaskReturn {
    pub fn from_enter_event(
        enter: Ssetmask,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SsetmaskReturn {})
    }
}

impl StatReturn {
    pub fn from_enter_event(
        enter: Stat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(StatReturn {
            stat: StatStruct::from_process(&process, enter.stat_buf_out as u64)?,
        })
    }
}

impl Stat64Return {
    pub fn from_enter_event(
        enter: Stat64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Stat64Return {})
    }
}

impl StatfsReturn {
    pub fn from_enter_event(
        enter: Statfs,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(StatfsReturn {})
    }
}

impl Statfs64Return {
    pub fn from_enter_event(
        enter: Statfs64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Statfs64Return {})
    }
}

impl StatxReturn {
    pub fn from_enter_event(
        enter: Statx,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(StatxReturn {})
    }
}

impl StimeReturn {
    pub fn from_enter_event(
        enter: Stime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(StimeReturn {})
    }
}

impl Stime32Return {
    pub fn from_enter_event(
        enter: Stime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Stime32Return {})
    }
}

impl SubpageProtReturn {
    pub fn from_enter_event(
        enter: SubpageProt,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SubpageProtReturn {})
    }
}

impl SwapcontextReturn {
    pub fn from_enter_event(
        enter: Swapcontext,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SwapcontextReturn {})
    }
}

impl SwapoffReturn {
    pub fn from_enter_event(
        enter: Swapoff,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SwapoffReturn {})
    }
}

impl SwaponReturn {
    pub fn from_enter_event(
        enter: Swapon,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SwaponReturn {})
    }
}

impl SwitchEndianReturn {
    pub fn from_enter_event(
        enter: SwitchEndian,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SwitchEndianReturn {})
    }
}

impl SymlinkReturn {
    pub fn from_enter_event(
        enter: Symlink,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SymlinkReturn {})
    }
}

impl SymlinkatReturn {
    pub fn from_enter_event(
        enter: Symlinkat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SymlinkatReturn {})
    }
}

impl SyncReturn {
    pub fn from_enter_event(
        enter: Sync,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SyncReturn {})
    }
}

impl SyncFileRangeReturn {
    pub fn from_enter_event(
        enter: SyncFileRange,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SyncFileRangeReturn {})
    }
}

impl SyncFileRange2Return {
    pub fn from_enter_event(
        enter: SyncFileRange2,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SyncFileRange2Return {})
    }
}

impl SyncfsReturn {
    pub fn from_enter_event(
        enter: Syncfs,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SyncfsReturn {})
    }
}

impl SysctlReturn {
    pub fn from_enter_event(
        enter: Sysctl,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SysctlReturn {})
    }
}

impl SysfsReturn {
    pub fn from_enter_event(
        enter: Sysfs,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SysfsReturn {})
    }
}

impl SysinfoReturn {
    pub fn from_enter_event(
        enter: Sysinfo,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SysinfoReturn {})
    }
}

impl SyslogReturn {
    pub fn from_enter_event(
        enter: Syslog,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SyslogReturn {})
    }
}

impl SysmipsReturn {
    pub fn from_enter_event(
        enter: Sysmips,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(SysmipsReturn {})
    }
}

impl TeeReturn {
    pub fn from_enter_event(
        enter: Tee,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TeeReturn {})
    }
}

impl TgkillReturn {
    pub fn from_enter_event(
        enter: Tgkill,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TgkillReturn {})
    }
}

impl TimeReturn {
    pub fn from_enter_event(
        enter: Time,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimeReturn {})
    }
}

impl Time32Return {
    pub fn from_enter_event(
        enter: Time32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Time32Return {})
    }
}

impl TimerCreateReturn {
    pub fn from_enter_event(
        enter: TimerCreate,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerCreateReturn {})
    }
}

impl TimerDeleteReturn {
    pub fn from_enter_event(
        enter: TimerDelete,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerDeleteReturn {})
    }
}

impl TimerGetoverrunReturn {
    pub fn from_enter_event(
        enter: TimerGetoverrun,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerGetoverrunReturn {})
    }
}

impl TimerGettimeReturn {
    pub fn from_enter_event(
        enter: TimerGettime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerGettimeReturn {})
    }
}

impl TimerGettime32Return {
    pub fn from_enter_event(
        enter: TimerGettime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerGettime32Return {})
    }
}

impl TimerSettimeReturn {
    pub fn from_enter_event(
        enter: TimerSettime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerSettimeReturn {})
    }
}

impl TimerSettime32Return {
    pub fn from_enter_event(
        enter: TimerSettime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerSettime32Return {})
    }
}

impl TimerfdCreateReturn {
    pub fn from_enter_event(
        enter: TimerfdCreate,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerfdCreateReturn {})
    }
}

impl TimerfdGettimeReturn {
    pub fn from_enter_event(
        enter: TimerfdGettime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerfdGettimeReturn {})
    }
}

impl TimerfdGettime32Return {
    pub fn from_enter_event(
        enter: TimerfdGettime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerfdGettime32Return {})
    }
}

impl TimerfdSettimeReturn {
    pub fn from_enter_event(
        enter: TimerfdSettime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerfdSettimeReturn {})
    }
}

impl TimerfdSettime32Return {
    pub fn from_enter_event(
        enter: TimerfdSettime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimerfdSettime32Return {})
    }
}

impl TimesReturn {
    pub fn from_enter_event(
        enter: Times,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TimesReturn {})
    }
}

impl TkillReturn {
    pub fn from_enter_event(
        enter: Tkill,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TkillReturn {})
    }
}

impl TruncateReturn {
    pub fn from_enter_event(
        enter: Truncate,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(TruncateReturn {})
    }
}

impl Truncate64Return {
    pub fn from_enter_event(
        enter: Truncate64,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Truncate64Return {})
    }
}

impl UmaskReturn {
    pub fn from_enter_event(
        enter: Umask,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UmaskReturn {})
    }
}

impl UmountReturn {
    pub fn from_enter_event(
        enter: Umount,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UmountReturn {})
    }
}

impl UnameReturn {
    pub fn from_enter_event(
        enter: Uname,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UnameReturn {})
    }
}

impl UnlinkReturn {
    pub fn from_enter_event(
        enter: Unlink,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UnlinkReturn {})
    }
}

impl UnlinkatReturn {
    pub fn from_enter_event(
        enter: Unlinkat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UnlinkatReturn {})
    }
}

impl UnshareReturn {
    pub fn from_enter_event(
        enter: Unshare,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UnshareReturn {})
    }
}

impl UselibReturn {
    pub fn from_enter_event(
        enter: Uselib,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UselibReturn {})
    }
}

impl UserfaultfdReturn {
    pub fn from_enter_event(
        enter: Userfaultfd,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UserfaultfdReturn {})
    }
}

impl UstatReturn {
    pub fn from_enter_event(
        enter: Ustat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UstatReturn {})
    }
}

impl UtimeReturn {
    pub fn from_enter_event(
        enter: Utime,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UtimeReturn {})
    }
}

impl Utime32Return {
    pub fn from_enter_event(
        enter: Utime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Utime32Return {})
    }
}

impl UtimensatReturn {
    pub fn from_enter_event(
        enter: Utimensat,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UtimensatReturn {})
    }
}

impl UtimensatTime32Return {
    pub fn from_enter_event(
        enter: UtimensatTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UtimensatTime32Return {})
    }
}

impl UtimesReturn {
    pub fn from_enter_event(
        enter: Utimes,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UtimesReturn {})
    }
}

impl UtimesTime32Return {
    pub fn from_enter_event(
        enter: UtimesTime32,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UtimesTime32Return {})
    }
}

impl UtrapInstallReturn {
    pub fn from_enter_event(
        enter: UtrapInstall,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(UtrapInstallReturn {})
    }
}

impl VforkReturn {
    pub fn from_enter_event(
        enter: Vfork,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(VforkReturn {})
    }
}

impl VhangupReturn {
    pub fn from_enter_event(
        enter: Vhangup,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(VhangupReturn {})
    }
}

impl Vm86Return {
    pub fn from_enter_event(
        enter: Vm86,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Vm86Return {})
    }
}

impl Vm86oldReturn {
    pub fn from_enter_event(
        enter: Vm86old,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Vm86oldReturn {})
    }
}

impl VmspliceReturn {
    pub fn from_enter_event(
        enter: Vmsplice,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(VmspliceReturn {})
    }
}

impl Wait4Return {
    pub fn from_enter_event(
        enter: Wait4,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(Wait4Return {})
    }
}

impl WaitidReturn {
    pub fn from_enter_event(
        enter: Waitid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(WaitidReturn {})
    }
}

impl WaitpidReturn {
    pub fn from_enter_event(
        enter: Waitpid,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(WaitpidReturn {})
    }
}

impl WriteReturn {
    pub fn from_enter_event(
        enter: Write,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(WriteReturn {})
    }
}

impl WritevReturn {
    pub fn from_enter_event(
        enter: Writev,
        retval: i64,
        process: &StoppedProcess,
    ) -> Result<Self, OsError> {
        Ok(WritevReturn {})
    }
}
