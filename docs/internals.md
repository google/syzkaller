# How syzkaller works

Generic description of how syzkaller works are [below](internals.md#overview).

Linux kernel specific internals can be found [here](linux/internals.md).

## Overview

The process structure for the syzkaller system is shown in the following diagram;
red labels indicate corresponding configuration options.

![Process structure for syzkaller](process_structure.png?raw=true)

The `syz-manager` process starts, monitors and restarts several VM instances, and starts a `syz-fuzzer` process inside of the VMs.
`syz-manager` is responsible for persistent corpus and crash storage.
It runs on a host with stable kernel which does not experience white-noise fuzzer load.

The `syz-fuzzer` process runs inside of presumably unstable VMs.
The `syz-fuzzer` guides fuzzing process (input generation, mutation, minimization, etc.) and sends inputs that trigger new coverage back to the `syz-manager` process via RPC.
It also starts transient `syz-executor` processes.

Each `syz-executor` process executes a single input (a sequence of syscalls).
It accepts the program to execute from the `syz-fuzzer` process and sends results back.
It is designed to be as simple as possible (to not interfere with fuzzing process), written in C++, compiled as static binary and uses shared memory for communication.

## Syscall descriptions

The `syz-fuzzer` process generates programs to be executed by `syz-executor` based on syscall descriptions described [here](syscall_descriptions.md).

## Coverage

Syzkaller is a coverage-guided fuzzer. The details about coverage collection can be found [here](coverage.md).

## Crash reports

When `syzkaller` finds a crasher, it saves information about it into `workdir/crashes` directory.
The directory contains one subdirectory per unique crash type.
Each subdirectory contains a `description` file with a unique string identifying the crash (intended for bug identification and deduplication);
and up to 100 `logN` and `reportN` files, one pair per test machine crash:
```
 - crashes/
   - 6e512290efa36515a7a27e53623304d20d1c3e
     - description
     - log0
     - report0
     - log1
     - report1
     ...
   - 77c578906abe311d06227b9dc3bffa4c52676f
     - description
     - log0
     - report0
     ...
```

Descriptions are extracted using a set of [regular expressions](/pkg/report/).
This set may need to be extended if you are using a different kernel architecture, or are just seeing a previously unseen kernel error messages.

`logN` files contain raw `syzkaller` logs and include kernel console output as well as programs executed before the crash.
These logs can be fed to `syz-repro` tool for [crash location and minimization](reproducing_crashes.md),
or to `syz-execprog` tool for [manual localization](executing_syzkaller_programs.md).
`reportN` files contain post-processed and symbolized kernel crash reports (e.g. a KASAN report).
Normally you need just 1 pair of these files (i.e. `log0` and `report0`), because they all presumably describe the same kernel bug.
However, `syzkaller` saves up to 100 of them for the case when the crash is poorly reproducible, or if you just want to look at a set of crash reports to infer some similarities or differences.

There are 3 special types of crashes:
 - `no output from test machine`: the test machine produces no output whatsoever
 - `lost connection to test machine`: the ssh connection to the machine was unexpectedly closed
 - `test machine is not executing programs`: the machine looks alive, but no test programs were executed for long period of time

Most likely you won't see `reportN` files for these crashes (e.g. if there is no output from the test machine, there is nothing to put into report).
Sometimes these crashes indicate a bug in `syzkaller` itself (especially if you see a Go panic message in the logs).
However, frequently they mean a kernel lockup or something similarly bad (here are just a few examples of bugs found this way:
[1](https://groups.google.com/d/msg/syzkaller/zfuHHRXL7Zg/Tc5rK8bdCAAJ),
[2](https://groups.google.com/d/msg/syzkaller/kY_ml6TCm9A/wDd5fYFXBQAJ),
[3](https://groups.google.com/d/msg/syzkaller/OM7CXieBCoY/etzvFPX3AQAJ)).
