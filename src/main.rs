use std::collections::HashMap;
use std::env::args_os;
use std::fs::File;
use std::io::{copy, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use dry::FingerprintEvent;
use dry::paths::SyscallsWithPathArgs;
use dry::TraceableCommand;

type Error = Box<dyn std::error::Error + 'static>;

#[derive(Debug, Serialize, Deserialize)]
enum FsInfoData {
    NotFound,
    PermissionDenied,
    Meta,
    File {
        modified_time: SystemTime,
        size: u64,
    },
    Directory {
        modified_time: SystemTime,
        number_entries: u64,
    },
}


#[derive(Debug, Serialize, Deserialize)]
struct FsInfo {
    data: FsInfoData,
    #[serde(with = "dry::util::serde_hex")]
    checksum: Vec<u8>,
    success: bool,
}

impl FsInfo {
    pub fn collect<A>(path: A) -> Result<Self, crate::Error> where A: AsRef<Path> {
        match std::fs::metadata(path.as_ref()) {
            Ok(ref m) if m.is_file() => {
                let mut hash = Sha256::new();
                let mut file = File::open(path.as_ref())?;
                copy(&mut file, &mut hash)?;

                Ok(FsInfo {
                    data: FsInfoData::File {
                        modified_time: m.modified()?,
                        size: m.len(),
                    },
                    checksum: hash.result().to_vec(),
                    success: true,
                })
            }
            Ok(ref m) if m.is_dir() => {
                let entries: Result<Vec<_>, _> = std::fs::read_dir(path.as_ref())?.collect();
                let mut entries = entries?;
                entries.sort_by_key(|e| e.file_name());
                let mut hash = Sha256::new();
                for p in entries.iter() {
                    hash.input(p.file_name().as_os_str().as_bytes());
                    // TODO: Add filetype to hash
                }

                Ok(FsInfo {
                    data: FsInfoData::Directory {
                        modified_time: m.modified()?,
                        number_entries: entries.len() as u64,
                    },
                    checksum: hash.result().to_vec(),
                    success: true,
                })
            }
            Ok(_) => {
                Ok(FsInfo {
                    data: FsInfoData::Meta,
                    checksum: vec![2; 32],
                    success: true,
                })
            }
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied => Ok(FsInfo {
                data: FsInfoData::PermissionDenied,
                checksum: vec![0; 32],
                success: false,
            }),
            Err(ref e) if e.kind() == ErrorKind::NotFound => Ok(FsInfo {
                data: FsInfoData::NotFound,
                checksum: vec![1; 32],
                success: false,
            }),
            Err(e) => Err(e)?
        }
    }
}

impl PartialEq for FsInfo {
    fn eq(&self, other: &Self) -> bool {
        use FsInfoData::*;
        match (&self.data, &other.data) {
            (PermissionDenied, PermissionDenied) => true,
            (NotFound, NotFound) => true,
            (File { .. }, File { .. }) => self.checksum == other.checksum,
            (Directory { .. }, Directory { .. }) => self.checksum == other.checksum,
            _ => false,
        }
    }
}

fn main() -> Result<(), Error> {
    let mut args = args_os();
    let _current_prog = args.next();
    let prog = match args.next() {
        Some(v) => v,
        None => return Err("Need to specify a program to run".into()),
    };

    let mut hasher = sha2::Sha256::new().chain(prog.as_bytes());
    let mut trace = Command::new(prog);
    for a in args {
        hasher.input(a.as_bytes());
        trace.arg(a);
    }
    let digest = hasher.result();
    let hexdigest = hex::encode(digest);
    let cache_path = Path::new(&hexdigest);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    if cache_path.exists() {
        for entry in std::fs::read_dir(cache_path)? {
            let entry = match entry {
                Ok(x) => x,
                Err(_) => continue,
            };
            match entry.file_type() {
                Ok(x) if x.is_file() => (),
                _ => continue,
            };
            let path = entry.path();
            eprintln!("Trying cache entry: {:?}", path);
            let file = File::open(path)?;
            let map: HashMap<PathBuf, FsInfo> = serde_json::from_reader(file)?;
            let mut entry_matching = true;
            for (k, cache_info) in map {
                let current_into = match FsInfo::collect(&k) {
                    Ok(v) => v,
                    Err(e) => {
                        entry_matching = false;
                        eprintln!("Could not collect info on: {:?} - {}", k, e);
                        continue;
                    }
                };

                if current_into != cache_info {
                    entry_matching = false;
                    eprintln!("Cache entry not up to date: {:?} - {:?} != {:?}", k, current_into, cache_info);
                }
            }

            if entry_matching {
                eprintln!("Cache entry matches, skipping...");
                return Ok(());
            }
        }
    }


    let trace = trace.spawn_traced()?;

    let mut last_touch = HashMap::<u32, _>::new();
    let mut paths_touched = HashMap::new();

    for ev in trace {
        let mut ev = ev?;

        use FingerprintEvent::*;
        match ev.event() {
            SyscallEnter { .. } => {
                let paths = match SyscallsWithPathArgs::from_fingerprint(&mut ev)? {
                    Some(x) => x.into_iter(),
                    None => continue,
                };
                for p in paths.clone() {
                    use std::collections::hash_map::Entry;
                    match paths_touched.entry(p) {
                        Entry::Vacant(v) => {
                            let info = FsInfo::collect(v.key())?;
                            v.insert(info);
                        }
                        Entry::Occupied(_) => (),
                    }
                }
                last_touch.insert(ev.pid(), paths);
            }
            SyscallExit { is_error, .. } => {
                if let Some(path) = last_touch.remove(&ev.pid()) {
                    for p in path {
                        paths_touched.get_mut(&p).expect("Paths inserted recently")
                            .success = !is_error;
                    }
                }
            }
            _ => (),
        }
    }

    std::fs::create_dir_all(cache_path)?;
    let mut fallback = 0;
    let f = loop {
        let p = cache_path.join(format!("{}-{}.entry", now, fallback));
        fallback = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(p) {
            Ok(f) => break f,
            Err(_) if fallback < 100 => fallback + 1,
            Err(x) => Err(x)?
        }
    };

    serde_json::to_writer(f, &paths_touched)?;

    Ok(())
}
