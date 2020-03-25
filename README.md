# DRY
Dry is a prototype of a more user-friendly `dvc run`. Instead of manually adding all
dependencies, `dry` uses the `ptrace` API (as used by `strace`, `gdb`, ...) to 
recognize inputs and outputs of a command. This information is then stored in a
`.dvc` that can be used with other normal `dvc` commands.  

## Demo
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

## Implementation details
`dry` tries to pull the inputs of the command by tracing the syscalls that are executed. This is done via the
`ptrace` API, also used by the `strace` tool. As the API is quite clunky on older kernels, `dry` requires Linux 
5.3 or above. Also, its is developed and tested on x86_64 only. 

Things the are considered input:
* Every **file** in the current repository
