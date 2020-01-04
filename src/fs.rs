use std::fs::{File, metadata, DirEntry};
use std::io::copy as io_copy_all;
use std::io::ErrorKind as IOErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

#[derive(Debug, Serialize, Deserialize)]
pub enum FsFingerprint {
    NotFound,
    PermissionDenied,
    Meta,
    File {
        #[serde(with = "crate::util::serde_hex")]
        checksum: Vec<u8>,
        modified_time: SystemTime,
        size: u64,
    },
    Directory {
        #[serde(with = "crate::util::serde_hex")]
        checksum: Vec<u8>,
        modified_time: SystemTime,
        number_entries: u64,
    },
}


fn checksum_file(path: &Path) -> crate::Result<Vec<u8>> {
    let mut hash = Sha256::new();
    let mut file = File::open(path)?;
    io_copy_all(&mut file, &mut hash)?;

    Ok(hash.result().to_vec())
}

fn checksum_dir(dir_entries: &[DirEntry]) -> crate::Result<Vec<u8>> {
    let mut hash = Sha256::new();
    for p in dir_entries {
        hash.input(p.file_name().as_os_str().as_bytes());
        // TODO: Add filetype to hash
    }
    Ok(hash.result().to_vec())
}

fn dir_entries(path: &Path) -> crate::Result<Vec<DirEntry>> {
    let entries: Result<Vec<_>, _> = std::fs::read_dir(path)?.collect();
    let mut entries = entries?;
    entries.sort_by_key(|e| e.file_name());
    Ok(entries)
}

impl FsFingerprint {
    pub fn collect<A>(path: A) -> Result<Self, crate::Error> where A: AsRef<Path> {
        match std::fs::metadata(path.as_ref()) {
            Ok(ref m) if m.is_file() => {
                Ok(FsFingerprint::File {
                    modified_time: m.modified()?,
                    size: m.len(),
                    checksum: checksum_file(path.as_ref())?,
                })
            }
            Ok(ref m) if m.is_dir() => {
                let entries = dir_entries(path.as_ref())?;
                Ok(FsFingerprint::Directory {
                    modified_time: m.modified()?,
                    number_entries: entries.len() as u64,
                    checksum: checksum_dir(&entries)?,
                })
            }
            Ok(_) => {
                Ok(FsFingerprint::Meta)
            }
            Err(ref e) if e.kind() == IOErrorKind::PermissionDenied => Ok(FsFingerprint::PermissionDenied),
            Err(ref e) if e.kind() == IOErrorKind::NotFound => Ok(FsFingerprint::NotFound),
            Err(e) => Err(e)?
        }
    }

    pub fn equals_path(&self, path: &Path) -> bool {
        use FsFingerprint::*;

        match (&self, metadata(path)) {
            (PermissionDenied, Err(ref e)) if e.kind() == IOErrorKind::PermissionDenied => true,
            (NotFound, Err(ref e)) if e.kind() == IOErrorKind::NotFound => true,
            (File { checksum, modified_time, size }, Ok(ref v)) if v.is_file() => {
                let time_equals = v.modified().map(|ref m| m == modified_time).unwrap_or(false);
                let size_equals = v.len() == *size;
                if time_equals && size_equals {
                    true
                } else {
                    checksum_file(path)
                        .map(|c| &c == checksum)
                        .unwrap_or(false)
                }
            }
            (Directory { checksum, modified_time, number_entries }, Ok(ref v)) if v.is_dir() => {
                let time_equals = v.modified().map(|ref m| m == modified_time).unwrap_or(false);
                let entries = match dir_entries(path) {
                    Ok(e) => e,
                    Err(_) => return false,
                };
                let n_entries_equal = entries.len() as u64 == *number_entries;
                if time_equals && n_entries_equal {
                    true
                } else {
                    checksum_dir(&entries)
                        .map(|c| &c == checksum)
                        .unwrap_or(false)
                }
            }
            _ => false,
        }
    }
}

impl PartialEq for FsFingerprint {
    fn eq(&self, other: &Self) -> bool {
        use FsFingerprint::*;
        match (&self, &other) {
            (PermissionDenied, PermissionDenied) => true,
            (NotFound, NotFound) => true,
            (
                File { checksum: own_checksum, .. },
                File { checksum: other_checksum, .. },
            ) => own_checksum == other_checksum,
            (
                Directory { checksum: own_checksum, .. },
                Directory { checksum: other_checksum, .. },
            ) => own_checksum == other_checksum,
            _ => false,
        }
    }
}
