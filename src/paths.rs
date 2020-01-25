use crate::util::TupleIterator;
use crate::Fingerprint;
use crate::FingerprintEvent;
use std::path::PathBuf;

#[derive(Debug)]
pub enum SyscallsWithPathArgs {
    Open(PathBuf),
    Stat(PathBuf),
    LStat(PathBuf),
    Access(PathBuf),
    Execve(PathBuf),
    Truncate(PathBuf),
    Chdir(PathBuf),
    Rename(PathBuf, PathBuf),
    Mkdir(PathBuf),
    Rmdir(PathBuf),
    Creat(PathBuf),
    Link(PathBuf, PathBuf),
    Unlink(PathBuf),
    Symlink(PathBuf, PathBuf),
    ReadLink(PathBuf),
    Chmod(PathBuf),
    Chown(PathBuf),
    LChown(PathBuf),
    Statfs(PathBuf),
    PivotRoot(PathBuf),
    Chroot(PathBuf),
    SetXAttr(PathBuf),
    LSetXAttr(PathBuf),
    GetXAttr(PathBuf),
    LGetXAttr(PathBuf),
    ListXAttr(PathBuf),
    LListXAttr(PathBuf),
    RemoveXAttr(PathBuf),
    LRemoveXAttr(PathBuf),
    UTimes(PathBuf),
    INotifyAddWatch(PathBuf),
    OpenAt(PathBuf),
    MkdirAt(PathBuf),
    MkNodAt(PathBuf),
    FChownAt(PathBuf),
    FUTimesAt(PathBuf),
    NewFStatAt(PathBuf),
    UnlinkAt(PathBuf),
    RenameAt(PathBuf, PathBuf),
    LinkAt(PathBuf, PathBuf),
    SymlinkAt(PathBuf, PathBuf),
    ReadLinkAt(PathBuf),
    FChmodAt(PathBuf),
    FAccessAt(PathBuf),
    UTimeNSAt(PathBuf),
    NameToHandleAt(PathBuf),
    RenameAt2(PathBuf, PathBuf),
    ExecveAt(PathBuf),
}

impl SyscallsWithPathArgs {
    pub fn from_fingerprint(ev: &mut Fingerprint) -> crate::Result<Option<Self>> {
        use FingerprintEvent::*;
        let (syscall_number, args) = match ev.event() {
            SyscallEnter {
                syscall_number,
                args,
            } => (syscall_number, args),
            _ => return Ok(None),
        };

        use SyscallsWithPathArgs::*;
        let res = match syscall_number {
            2 => {
                let s = ev.read_os_string(args[0])?;
                Open(s.into())
            }
            4 => {
                let s = ev.read_os_string(args[0])?;
                Stat(s.into())
            }
            6 => {
                let s = ev.read_os_string(args[0])?;
                LStat(s.into())
            }
            21 => {
                let s = ev.read_os_string(args[0])?;
                Access(s.into())
            }
            59 => {
                let s = ev.read_os_string(args[0])?;
                Execve(s.into())
            }
            76 => {
                let s = ev.read_os_string(args[0])?;
                Truncate(s.into())
            }
            80 => {
                let s = ev.read_os_string(args[0])?;
                Chdir(s.into())
            }
            82 => {
                let a = ev.read_os_string(args[0])?;
                let b = ev.read_os_string(args[1])?;
                Rename(a.into(), b.into())
            }
            83 => {
                let s = ev.read_os_string(args[0])?;
                Mkdir(s.into())
            }
            84 => {
                let s = ev.read_os_string(args[0])?;
                Rmdir(s.into())
            }
            85 => {
                let s = ev.read_os_string(args[0])?;
                Creat(s.into())
            }
            86 => {
                let a = ev.read_os_string(args[0])?;
                let b = ev.read_os_string(args[1])?;
                Link(a.into(), b.into())
            }
            87 => {
                let s = ev.read_os_string(args[0])?;
                Unlink(s.into())
            }
            88 => {
                let a = ev.read_os_string(args[0])?;
                let b = ev.read_os_string(args[1])?;
                Symlink(a.into(), b.into())
            }
            89 => {
                let s = ev.read_os_string(args[0])?;
                ReadLink(s.into())
            }
            90 => {
                let s = ev.read_os_string(args[0])?;
                Chmod(s.into())
            }
            92 => {
                let s = ev.read_os_string(args[0])?;
                Chown(s.into())
            }
            94 => {
                let s = ev.read_os_string(args[0])?;
                LChown(s.into())
            }
            137 => {
                let s = ev.read_os_string(args[0])?;
                Statfs(s.into())
            }
            155 => {
                let s = ev.read_os_string(args[0])?;
                PivotRoot(s.into())
            }
            161 => {
                let s = ev.read_os_string(args[0])?;
                Chroot(s.into())
            }
            188 => {
                let s = ev.read_os_string(args[0])?;
                SetXAttr(s.into())
            }
            189 => {
                let s = ev.read_os_string(args[0])?;
                LSetXAttr(s.into())
            }
            191 => {
                let s = ev.read_os_string(args[0])?;
                GetXAttr(s.into())
            }
            192 => {
                let s = ev.read_os_string(args[0])?;
                LGetXAttr(s.into())
            }
            194 => {
                let s = ev.read_os_string(args[0])?;
                ListXAttr(s.into())
            }
            195 => {
                let s = ev.read_os_string(args[0])?;
                LListXAttr(s.into())
            }
            197 => {
                let s = ev.read_os_string(args[0])?;
                RemoveXAttr(s.into())
            }
            198 => {
                let s = ev.read_os_string(args[0])?;
                LRemoveXAttr(s.into())
            }
            235 => {
                let s = ev.read_os_string(args[0])?;
                UTimes(s.into())
            }
            254 => {
                let s = ev.read_os_string(args[1])?;
                INotifyAddWatch(s.into())
            }
            257 => {
                // TODO: Handle dir_fd argument
                let s = ev.read_os_string(args[1])?;
                OpenAt(s.into())
            }
            258 => {
                let s = ev.read_os_string(args[1])?;
                MkdirAt(s.into())
            }
            259 => {
                let s = ev.read_os_string(args[1])?;
                MkNodAt(s.into())
            }
            260 => {
                let s = ev.read_os_string(args[1])?;
                FChownAt(s.into())
            }
            261 => {
                let s = ev.read_os_string(args[1])?;
                FUTimesAt(s.into())
            }
            262 => {
                let s = ev.read_os_string(args[1])?;
                NewFStatAt(s.into())
            }
            263 => {
                let s = ev.read_os_string(args[1])?;
                UnlinkAt(s.into())
            }
            264 => {
                let a = ev.read_os_string(args[1])?;
                let b = ev.read_os_string(args[3])?;
                RenameAt(a.into(), b.into())
            }
            265 => {
                let a = ev.read_os_string(args[1])?;
                let b = ev.read_os_string(args[3])?;
                LinkAt(a.into(), b.into())
            }
            266 => {
                let a = ev.read_os_string(args[0])?;
                let b = ev.read_os_string(args[2])?;
                SymlinkAt(a.into(), b.into())
            }
            267 => {
                let s = ev.read_os_string(args[1])?;
                ReadLinkAt(s.into())
            }
            268 => {
                let s = ev.read_os_string(args[1])?;
                FChmodAt(s.into())
            }
            269 => {
                let s = ev.read_os_string(args[1])?;
                FAccessAt(s.into())
            }
            280 => {
                let s = ev.read_os_string(args[1])?;
                UTimeNSAt(s.into())
            }
            303 => {
                let s = ev.read_os_string(args[1])?;
                NameToHandleAt(s.into())
            }
            316 => {
                let a = ev.read_os_string(args[1])?;
                let b = ev.read_os_string(args[3])?;
                RenameAt2(a.into(), b.into())
            }
            322 => {
                let s = ev.read_os_string(args[1])?;
                ExecveAt(s.into())
            }
            _ => return Ok(None),
        };
        Ok(Some(res))
    }
}

impl IntoIterator for SyscallsWithPathArgs {
    type Item = PathBuf;
    type IntoIter = TupleIterator<PathBuf>;

    fn into_iter(self) -> Self::IntoIter {
        use SyscallsWithPathArgs::*;
        match self {
            Open(a) | Stat(a) | LStat(a) | Access(a) | Execve(a) | Truncate(a) | Chdir(a)
            | Mkdir(a) | Rmdir(a) | Creat(a) | Unlink(a) | ReadLink(a) | Chmod(a) | Chown(a)
            | LChown(a) | Statfs(a) | PivotRoot(a) | Chroot(a) | SetXAttr(a) | LSetXAttr(a)
            | GetXAttr(a) | LGetXAttr(a) | ListXAttr(a) | LListXAttr(a) | RemoveXAttr(a)
            | LRemoveXAttr(a) | UTimes(a) | INotifyAddWatch(a) | OpenAt(a) | MkdirAt(a)
            | MkNodAt(a) | FChownAt(a) | FUTimesAt(a) | NewFStatAt(a) | UnlinkAt(a)
            | ReadLinkAt(a) | FChmodAt(a) | FAccessAt(a) | UTimeNSAt(a) | NameToHandleAt(a)
            | ExecveAt(a) => TupleIterator::One(a),
            Link(a, b)
            | Rename(a, b)
            | Symlink(a, b)
            | RenameAt2(a, b)
            | SymlinkAt(a, b)
            | LinkAt(a, b)
            | RenameAt(a, b) => TupleIterator::Two(a, b),
        }
    }
}
