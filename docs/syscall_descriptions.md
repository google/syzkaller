# Syscall descriptions

`syzkaller` uses declarative description of syscall interfaces to manipulate
programs (sequences of syscalls). Below you can see (hopefully self-explanatory)
excerpt from the description:

```
open(file filename, flags flags[open_flags], mode flags[open_mode]) fd
read(fd fd, buf buffer[out], count len[buf])
close(fd fd)
open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
```

The description is contained in `sys/OS/*.txt` files.
For example see the [sys/linux/dev_snd_midi.txt](/sys/linux/dev_snd_midi.txt) file
for descriptions of the Linux MIDI interfaces.

A more formal description of the description syntax can be found [here](syscall_descriptions_syntax.md).

## Programs

The translated descriptions are then used to generate, mutate, execute, minimize, serialize
and deserialize programs. A program is a sequences of syscalls with concrete values for arguments.
Here is an example (of a textual representation) of a program:

```
r0 = open(&(0x7f0000000000)="./file0", 0x3, 0x9)
read(r0, &(0x7f0000000000), 42)
close(r0)
```

For actual manipulations `syzkaller` uses in-memory AST-like representation consisting of
`Call` and `Arg` values defined in [prog/prog.go](/prog/prog.go). That representation is used to
[analyze](/prog/analysis.go), [generate](/prog/rand.go), [mutate](/prog/mutation.go),
[minimize](/prog/minimization.go), [validate](/prog/validation.go), etc programs.

The in-memory representation can be [transformed](/prog/encoding.go) to/from
textual form to store in on-disk corpus, show to humans, etc.

There is also another [binary representation](https://github.com/google/syzkaller/blob/master/prog/decodeexec.go)
of the programs (called `exec`), that is much simpler, does not contains rich type information (irreversible)
and is used for actual execution (interpretation) of programs by [executor](/executor/executor.cc).

## Describing new system calls

This section describes how to extend syzkaller to allow fuzz testing of a new system call;
this is particularly useful for kernel developers who are proposing new system calls.

Syscall interfaces are manually-written. There is an
[open issue](https://github.com/google/syzkaller/issues/590) to provide some aid
for this process and some ongoing work, but we are yet there.
There is also [headerparser](headerparser_usage.md) utility that can auto-generate
some parts of descriptions from header files.

First, add a declarative description of the new system call to the appropriate file:
 - Various `sys/linux/<subsystem>.txt` files hold system calls for particular kernel
   subsystems, for example `bpf` or `socket`.
 - [sys/linux/sys.txt](/sys/linux/sys.txt) holds descriptions for more general system calls.
 - An entirely new subsystem can be added as a new `sys/linux/<new>.txt` file.

The description of the syntax can be found [here](syscall_descriptions_syntax.md).

After adding/changing descriptions run:
```
make extract TARGETOS=linux SOURCEDIR=$KSRC
make generate
make
```

Here `make extract` generates/updates the `*.const` files.
`$KSRC` should point to the _latest_ kernel checkout.\
_Note_: for Linux the _latest_ kernel checkout generally means the
[mainline](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/) tree.\
However, in some cases we add descriptions for interfaces that are not in the mainline tree yet,
so if `make extract` complains about missing header files or constants undefined on all architectures,
try to use the latest [linux-next](https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/log/)
tree (or if it happens to be broken at the moment, try a slightly older linux-next tree).\
_Note_: `make extract` overwrites `.config` in `$KSRC` and `mrproper`'s it.

Then `make generate` updates generated code and `make` rebuilds binaries.\
Note: `make generate` does not require any kernel sources, native compilers, etc
and is pure text processing.
Note: `make generate` also updates the SYZ_REVISION under executor/defs.h, which
is required for machine check while running syz-manager. This should be taken care
of especially if you are trying to rebase with your own change on syscall description.

Note: _all_ generated files (`*.const`, `*.go`, `*.h`) are checked-in with the
`*.txt` changes in the same commit.

Note: `make extract` extracts constants for all architectures which requires
installed cross-compilers. If you get errors about missing compilers/libraries,
try `sudo make install_prerequisites` or install equivalent package for your distro.
Note: `sudo make install_prerequisites` will success even with some package failed to
install, `sudo apt-get update && sudo apt-get upgrade` might be required to make this
more efficient.

If you want to fuzz the new subsystem that you described locally, you may find
the `enable_syscalls` configuration parameter useful to specifically target
the new system calls.

When updating existing syzkaller descriptions, note, that unless there's a drastic
change in descriptions for a particular syscall, the programs that are already in
the corpus will be kept there, unless you manually clear them out (for example by
removing the `corpus.db` file).

## Description compilation internals

The process of compiling the textual syscall descriptions into machine-usable
form used by `syzkaller` to actually generate programs consists of 2 steps.

The first step is extraction of values of symbolic constants from kernel sources using
[syz-extract](/sys/syz-extract) utility. `syz-extract` generates a small C program that
includes kernel headers referenced by `include` directives, defines macros as specified
by `define` directives and prints values of symbolic constants.
Results are stored in `.const` files, one per arch.
For example, [sys/linux/dev_ptmx.txt](/sys/linux/dev_ptmx.txt) is translated into
[sys/linux/dev_ptmx_amd64.const](/sys/linux/dev_ptmx_amd64.const).

The second step is translation of descriptions into Go code using
[syz-sysgen](/sys/syz-sysgen) utility (the actual compiler code lives in
[pkg/ast](/pkg/ast/) and [pkg/compiler](/pkg/compiler/)).
This step uses syscall descriptions and the const files generated during the first step
and produces instantiations of `Syscall` and `Type` types defined in [prog/types.go](/prog/types.go).
Here is an [example](/sys/akaros/gen/amd64.go) of the compiler output for Akaros.
This step also generates some minimal syscall metadata for C++ code in
[executor/syscalls.h](/executor/syscalls.h).

## Non-mainline subsystems

`make extract` extracts constants for all `*.txt` files and for all supported architectures.
This may not work for subsystems that are not present in mainline kernel or if you have
problems with native kernel compilers, etc. In such cases the `syz-extract` utility
used by `make extract` can be run manually for single file/arch as:

```
make bin/syz-extract
bin/syz-extract -os linux -arch $ARCH -sourcedir $KSRC -builddir $LINUXBLD <new>.txt
make generate
make
```

`$ARCH` is one of `amd64`, `386` `arm64`, `arm`, `ppc64le`, `mips64le`.
If the subsystem is supported on several architectures, then run `syz-extract` for each arch.
`$LINUX` should point to kernel source checkout, which is configured for the
corresponding arch (i.e. you need to run `make ARCH=arch someconfig && make ARCH=arch` there first,
remember to add `CROSS_COMPILE=arm-linux-gnueabi-/aarch64-linux-gnu-/powerpc64le-linux-gnu-` if needed).
If the kernel was built into a separate directory (with `make O=output_dir`, remember to put .config
into output_dir, this will be helpful if you'd like to work on different arch at the same time)
then also set `$LINUXBLD` to the location of the build directory.
