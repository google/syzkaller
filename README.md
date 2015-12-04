# syzkaller - linux syscall fuzzer

`syzkaller` is a distributed, unsupervised, coverage-guided Linux syscall fuzzer.
It is meant to be used with [KASAN](https://www.kernel.org/doc/Documentation/kasan.txt) (`CONFIG_KASAN=y`),
[KTSAN](https://github.com/google/ktsan) (`CONFIG_KTSAN=y`),
or [KUBSAN] (http://developerblog.redhat.com/2014/10/16/gcc-undefined-behavior-sanitizer-ubsan/) ([patch](https://lkml.org/lkml/2014/10/20/181)).

Project [mailing list](https://groups.google.com/forum/#!forum/syzkaller).

List of [found bugs](https://github.com/google/syzkaller/wiki/Found-Bugs).

This is work-in-progress, some things may not work yet.

## Usage

Various components are needed to build and run syzkaller.

 - C compiler with coverage support
 - Linux kernel with coverage additions
 - QEMU and disk image
 - The syzkaller components

Setting each of these up is discussed in the following sections.

### C Compiler

Syzkaller is a coverage-guided fuzzer and so needs the kernel to be built with coverage support.
Therefore, a recent upstream version of GCC is needed. Coverage support is submitted to gcc in
revision 231296. Sync past it and build fresh gcc.

### Linux Kernel

As well as adding coverage support to the C compiler, the Linux kernel itself needs to be modified
to:
 - add support in the build system for the coverage options (under `CONFIG_SANCOV`)
 - add extra instrumentation on system call entry/exit (for a `CONFIG_SANCOV` build)
 - add code to track and report per-task coverage information.

This is all implemented in [this coverage patch](https://github.com/dvyukov/linux/commits/kcov);
once the patch is applied, the kernel should be configured with `CONFIG_SANCOV` plus `CONFIG_KASAN`
or `CONFIG_KTSAN`.

### QEMU Setup

Syzkaller runs its fuzzer processes inside QEMU virtual machines, so a working QEMU system is needed
&ndash; see [QEMU docs](http://wiki.qemu.org/Manual) for details.

In particular:

 - The fuzzing processes communicate with the outside world, so the VM image needs to include
   networking support.
 - The program files for the fuzzer processes are transmitted into the VM using SSH, so the VM image
   needs a running SSH server.
 - The VM's SSH configuration should be set up to allow root access for the identity that is
   included in the `master`'s configuration.  In other words, you should be able to do `ssh -i
   $SSHID -p $PORT root@localhost` without being prompted for a password (where `SSHID` is the SSH
   identification file and `PORT` is the port that are specified in the `manager` configuration
   file).

TODO: Describe how to support other types of VM other than QEMU.

### Syzkaller

The syzkaller tools are written in [Go](https://golang.org), so a Go compiler (>= 1.4) is needed
to build them.  Build with `make`, which generates compiled binaries in the `bin/` folder.

## Configuration

The operation of the syzkaller manager process is governed by a configuration file, passed at
invocation time with the `-config` option.  This configuration can be based on the
[example file](manager/example.cfg) `manager/example.cfg`; the file is in JSON format with the
following keys in its top-level object:

 - `name`: Name to use for this instance.
 - `http`: URL that will display information about the running manager process.
 - `master`: Location of the master process that the `manager` should communicate with.
 - `workdir`: Location of a working directory for the `manager` process. Outputs here include:
     - `<workdir>/qemu/logN-M-T`: log files
     - `<workdir>/qemu/imageN`: per-instance copies of the VM disk image
     - `<workdir>/crashes/crashN-T`: crash output files
 - `vmlinux`: Location of the `vmlinux` file that corresponds to the kernel being tested.
 - `type`: Type of virtual machine to use, e.g. `qemu`.
 - `count`: Number of VMs to run in parallel.
 - `procs`: Number of parallel test processes in each VM (4 or 8 would be a reasonable number).
 - `port`: Port that the manager process listens on for communications from the
   fuzzer processes running in the VMs.
 - `leak`: Detect memory leaks with kmemleak (very slow).
 - `params`: A JSON object containing VM configuation, specific to the particular `type` of VM. For
   `qemu` VMs, this configuration includes:
      - `kernel`: Location of the `bzImage` file for the kernel to be tested; this is passed as the
        `-kernel` option to `qemu-system-x86_64`.
      - `cmdline`: Additional command line options for the booting kernel, for example `root=/dev/sda1`.
      - `image`: Location of the disk image file for the QEMU instance; a copy of this file is passed as the
        `-hda` option to `qemu-system-x86_64`.
      - `sshkey`: Location (on the host machine) of an SSH identity to use for communicating with
        the virtual machine.
      - `fuzzer`: Location (on the host machine) of the syzkaller `fuzzer` binary.
      - `executor`: Location (on the host machine) of the syzkaller `executor` binary.
      - `port`: TCP port on the host machine that should be redirected to the SSH port (port 22) on
        the guest VM; this is passed as part of the `hostfwd` option to the `-net` option of
        `qemu-system-x86_64`.
      - `cpu`: Number of CPUs to simulate in the VM (*not currently used*).
      - `mem`: Amount of memory (in MiB) for the VM; this is passed as the `-m` option to
        `qemu-system-x86_64`.
 - `enable_syscalls`: List of syscalls to test (optional).
 - `disable_syscalls`: List of system calls that should be treated as disabled (optional).
 - `suppressions`: List of regexps for known bugs.


## Running syzkaller

First, start the master process as:
```
./master -workdir=./workdir -addr=myhost.com:48342 -http=myhost.com:29855
```

The command-line arguments for `master` are:

 - `-workdir`: Provide a directory on the host machine where fuzzing input data is stored. Two
   subdirectories of this directory are used:
    - `<workdir>/corpus/`: Fuzzing input corpus.
    - `<workdir>/crashers/`: Fuzzing inputs that cause crashes.
 - `-addr`: Provide the RPC address that `manager` processes will connect to.  This should match
   the `master` key in the `manager`'s configuration file.
 - `-http`: URL on which the `master` process will expose an HTTP interface.
 - `-v`: Verbosity (lower number is more verbose).

Then, start the manager process as:
```
./manager -config my.cfg
```

The `-config` command line option gives the location of the configuration file
[described above](configuration).

The `manager` process will wind up qemu virtual machines and start fuzzing in them.
If you open the HTTP address for the `master` (in our case `http://myhost.com:29855`),
you will see how corpus collection progresses.  This page also includes a link to
the HTTP address for the `manager` process, which displays information about the
status/progress of the VMs.


## Process Structure

The process structure for the syzkaller system is shown in the following diagram; red labels
indicate corresponding configuration options.

![Process structure for syzkaller](structure.png?raw=true)

The `master` process is responsible for persistent corpus and crash storage.
It communicates with one or more `manager` processes via RPC.

The `manager` process starts, monitors and restarts several VM instances (support for
physical machines is not implemented yet), and starts a `fuzzer` process inside of the VMs.
The `manager` process also serves as a persistent proxy between `fuzzer` processes and the `master` process.
As opposed to `fuzzer` processes, it runs on a host with stable kernel which does not
experience white-noise fuzzer load.

The `fuzzer` process runs inside of presumably unstable VMs (or physical machines under test).
The `fuzzer` guides fuzzing process itself (input generation, mutation, minimization, etc)
and sends inputs that trigger new coverage back to the `manager` process via RPC.
It also starts transient `executor` processes.

Each `executor` process executes a single input (a sequence of syscalls).
It accepts the program to execute from the `fuzzer` process and sends results back.
It is designed to be as simple as possible (to not interfere with fuzzing process),
written in C++, compiled as static binary and uses shared memory for communication.

## Syscall description

syzkaller uses declarative description of syscalls to generate, mutate, minimize,
serialize and deserialize programs (sequences of syscalls). Below you can see
(hopefully self-explanatory) excerpt from the description:

```
open(file filename, flags flags[open_flags], mode flags[open_mode]) fd
read(fd fd, buf buffer[out], count len[buf]) len[buf]
close(fd fd)
open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
```

The description is contained in `syzkaller/sys/sys.txt` file.

This is not an official Google product.
