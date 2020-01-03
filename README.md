# DRY
Don't repeat yourself: Cache the results of an **any** program, as long as the inputs have not changed

Its like [`dvc`](https://dvc.org/) but it reduces the burden of tracking which code was executed.
When developing a data pipeline, one often would like to re-run older versions of the pipeline, with
just a small code snippet changed. `dry` tries to streamline this process by automatically skipping steps
that stayed the same (kind of like make, but more general). 

# How it works (more like: how it should work in the future...)

On first run
```
dry my-program argument1 argument2 etc
```
`dry` checks the cache if this command has been run before. If not it will just run the command, as there is
nothing in the cache to take the results from. This run will create a cache entry.

If there is one (or more) match in the cache, further work is required. The cache entry contains **every**
input of the old execution, meaning a full list of every file that was read/written by the program. Only if 
[all](#implementation-details) of them match, the cached version of the outputs will be used.

If there are cache entries that match the command line, but not every input stayed the same, the command is 
executed again and will create a new cache entry.

## Implementation details
`dry` tries to pull the inputs of the command by tracing the syscalls that are executed. This is done via the
`ptrace` API, also used by the `strace` tool. As the API is quite clunky on older kernels, `dry` requires Linux 
5.3 or above. Also, its is developed and tested on x86_64 only. 

Things the are considered input:
* Opened files (includes shared libraries and configurations in `/etc`. Will most likely exclude stuff in `/dev` and 
  `/proc` in the future)
* environment variables: Again subject to change, as that seems quite brittle


## Demo
Current proof of concept just checks that all files referenced in syscalls are as they were when first introduced.
```
$ cargo run --release -- python3 -c "2 + 2"
    Finished release [optimized] target(s) in 0.02s
     Running `target/release/dry python3 -c '2 + 2'`

Process finished with exit code 0
```

On the second run:
```
cargo run --color=always --release -- python3 -c "2 + 2"
    Finished release [optimized] target(s) in 3.27s
     Running `target/release/dry python3 -c '2 + 2'`
Trying cache entry: "2bbf95ed128e93eff66451cfc6efcdf46fdb401edf25106f8c4afea30df6eaf7/1578065473-0.entry"
Cache entry matches, skipping...

Process finished with exit code 0
```

Cache entry are current just written to the working directory.
