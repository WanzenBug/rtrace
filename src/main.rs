use std::collections::HashMap;
use std::env::args_os;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use sha2::Digest;
use sha2::Sha256;

use dry::fs::FsFingerprint;
use dry::paths::SyscallsWithPathArgs;
use dry::FingerprintEvent;
use dry::TraceableCommand;

type Error = Box<dyn std::error::Error + 'static>;

fn main() -> Result<(), Error> {
    let mut args = args_os();
    let _current_prog = args.next();
    let prog = match args.next() {
        Some(v) => v,
        None => return Err("Need to specify a program to run".into()),
    };

    let mut hasher = Sha256::new().chain(prog.as_bytes());
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
            let map: HashMap<PathBuf, FsFingerprint> = serde_json::from_reader(file)?;
            let mut entry_matching = true;
            for (k, cache_info) in map {
                if !cache_info.equals_path(k.as_path()) {
                    entry_matching = false;
                    eprintln!("Entry for {} changed: {:?}", k.display(), cache_info);
                }
            }

            if entry_matching {
                eprintln!("Cache entry matches, skipping...");
                return Ok(());
            }
        }
    }

    let trace = trace.spawn_traced()?;

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
                eprintln!("paths = {:#?}", paths);
                for p in paths {
                    use std::collections::hash_map::Entry;
                    match paths_touched.entry(p) {
                        Entry::Vacant(v) => {
                            let info = FsFingerprint::collect(v.key())?;
                            v.insert(info);
                        }
                        Entry::Occupied(_) => (),
                    }
                }
            }
            _ => (),
        }
    }

    let current_paths: HashMap<_, _> = paths_touched
        .into_iter()
        .filter(|(k, v)| {
            if v.equals_path(k) {
                true
            } else {
                eprintln!("Path {} looks like an output", k.display());
                false
            }
        })
        .collect();

    std::fs::create_dir_all(cache_path)?;
    let mut fallback = 0;
    let f = loop {
        let p = cache_path.join(format!("{}-{}.entry", now, fallback));
        fallback = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(p)
        {
            Ok(f) => break f,
            Err(_) if fallback < 100 => fallback + 1,
            Err(x) => Err(x)?,
        }
    };

    serde_json::to_writer(f, &current_paths)?;

    Ok(())
}
