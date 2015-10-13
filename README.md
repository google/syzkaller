# syzkaller - linux syscall fuzzer

`syzkaller` is a distributed, unsupervised, coverage-guided Linux syscall fuzzer.
It is meant to be used with [KASAN](https://www.kernel.org/doc/Documentation/kasan.txt) (`CONFIG_KASAN=y`),
[KTSAN](https://github.com/google/ktsan) (`CONFIG_KTSAN=y`),
or [KUBSAN] (http://developerblog.redhat.com/2014/10/16/gcc-undefined-behavior-sanitizer-ubsan/) ([patch](https://lkml.org/lkml/2014/10/20/181)).

Project [mailing list](https://groups.google.com/forum/#!forum/syzkaller).

List of [found bugs](https://github.com/google/syzkaller/wiki/Found-Bugs).

This is work-in-progress, some things may not work yet.

## Usage

Coverage support is not upstreamed yet, so you need to apply [this patch](https://codereview.appspot.com/267910043)
to gcc (tested on revision 227353) and [this patch](https://github.com/dvyukov/linux/commit/5626fbd654b9f0ce037376bd95bfe8e9530e1313)
to kernel. Then build kernel with `CONFIG_KASAN` or `CONFIG_KTSAN` and the new `CONFIG_SANCOV`.

Then, build syzkaller with `make`.
The compiled binaries will be put in the `bin` folder.

Then, write manager config based on `manager/example.cfg`.

Then, start the master process as:
```
./master -workdir=./workdir -addr=myhost.com:48342 -http=myhost.com:29855
```

and start the manager process as:
```
./manager -config my.cfg
```

The manager process will wind up qemu virtual machines and start fuzzing in them.
If you open the HTTP address (in our case `http://myhost.com:29855`),
you will see how corpus collection progresses.

## Process Structure

Master process is responsible for persistent corpus and crash storage.
It communicates with one or more manager processes via RPC.

Manager process starts, monitors and restarts several VM instances (support for
physical machines is not implemented yet), and starts fuzzer process inside of the VMs.
Manager process also serves as a persistent proxy between fuzzer processes and the master process.
As opposed to fuzzer processes, it runs on a host with stable kernel which does not
experience white-noise fuzzer load.

Fuzzer process runs inside of presumably unstable VMs (or physical machines under test).
Fuzzer guides fuzzing process itself (input generation, mutation, minimization, etc)
and sends inputs that trigger new coverage back to the manager process via RPC.
It also starts transient executor processes.

Executor process executes a single input (a sequence of syscalls).
It accepts the program to execute from fuzzer process and sends results back.
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
