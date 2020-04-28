# rtrace - Rust bindings to ptrace API

Provide safe bindings to `ptrace`. This can be used to implement debuggers or other development tools
like `strace` or similar.

**NOTE**: This is optimized for Linux targets (with kernel >3.4) on x86_64. No other platform is
currently supported.

## Demo

The repo contains two sample programs:

* `dry` enhances [dvc](https://github.com/iterative/dvc/) with some convenience around creating a pipeline.
* `rtrace` is a simple re-implementation of `strace` in rust.

### dry
`dry` is a prototype of a more user-friendly `dvc run`. Instead of manually adding all
dependencies, `dry` uses the `ptrace` API (as used by `strace`, `gdb`, ...) to
recognize inputs and outputs of a command. This information is then stored in a
`.dvc` that can be used with other normal `dvc` commands.

```terminal
/test $ ll
total 12K
-rw-r--r--. 1 wanzenbug wanzenbug  14 Mar 25 15:07 input
-rw-r--r--. 1 wanzenbug wanzenbug  32 Mar 25 15:01 op.py
-rw-r--r--. 1 wanzenbug wanzenbug 256 Mar 25 15:06 stage.py
/test $ cat input
1
2
3
4
5
6
7
/test $ cat op.py
def op(a, b):
     return a + b
/test $ cat stage.py
from op import op

inputs = []
with open("input", "r") as lines:
   for line in lines:
      if not line.strip():
          continue
      inputs.append(int(line))

with open("output", "w") as output:
   for i in inputs:
      print(op(i, 2), file=output)
/test $ dry run -f test.dvc python stage.py
/test $ cat output
3
4
5
6
7
8
9
/test $ cat test.dvc
---
cmd: dry run -f test.dvc python stage.py
md5: ""
deps:
  - path: op.py
    md5: 4c5e633103f9c90a7a275928c3266455
  - path: input
    md5: 77c58f04583c86f78c51df158e3f35e8
  - path: stage.py
    md5: 1e0c1ae1f7d549148948a06e3237e8a3
outs:
  - path: output
    cache: true
    md5: 40754c006b40f76c0139286da37a7971
meta:
  created-by: dry
```

#### Implementation details
`dry` tries to pull the inputs of the command by tracing the syscalls that are executed.

Things the are considered input:
* Every **file** in the current repository

### rtrace

```
$ cargo run --bin rtrace --features=rtrace python3 -c "import json"
PID  5872|SyscallEnter(Execve(Execve { filename: "/home/mwanzenboeck/.cargo/bin/python3", argv: ["python3", "-c", "import json"], envp: ["CARGO=/home/mwanzenboeck/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo", ...] }))
PID  5872|SyscallExit(SyscallError(Os { code: 2, kind: NotFound, message: "No such file or directory" }))
PID  5872|SyscallEnter(Execve(Execve { filename: "/home/mwanzenboeck/.local/bin/python3", argv: ["python3", "-c", "import json"], envp: ["CARGO=/home/mwanzenboeck/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo", ...] }))
...
PID  5872|SyscallEnter(ExitGroup(ExitGroup { code: 0 }))
PID  5872|Exit(0)
```
