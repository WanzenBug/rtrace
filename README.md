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
Current status is only a proof-of-concept of the `ptrace` API. It will report any file opened by syscalls
of the command or any of its children. It will also indicate if the open call was successful or not.

```
$ cargo run -- python -c "import re"
...
22151: true  	"/usr/lib64/python2.7/sysconfig.pyc"
22151: false  	"/usr/lib64/python2.7/re.so"
22151: false  	"/usr/lib64/python2.7/remodule.so"
22151: true  	"/usr/lib64/python2.7/re.py"
22151: true  	"/usr/lib64/python2.7/re.pyc"
22151: false  	"/usr/lib64/python2.7/sre_compile.so"
22151: false  	"/usr/lib64/python2.7/sre_compilemodule.so"
...
```
