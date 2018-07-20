# Syscall descriptions

`syzkaller` uses declarative description of syscalls to generate, mutate, minimize, serialize and deserialize programs (sequences of syscalls).
Below you can see (hopefully self-explanatory) excerpt from the description:

```
open(file filename, flags flags[open_flags], mode flags[open_mode]) fd
read(fd fd, buf buffer[out], count len[buf]) len[buf]
close(fd fd)
open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
```

The description is contained in `sys/linux/*.txt` files.
For example see the [sys/linux/sys.txt](/sys/linux/sys.txt) file.

## Syntax

The description of the syntax can be found [here](syscall_descriptions_syntax.md).

## Code generation

Textual syscall descriptions are translated into code used by `syzkaller`.
This process consists of 2 steps.
The first step is extraction of values of symbolic constants from Linux sources using `syz-extract` utility.
`syz-extract` generates a small C program that includes kernel headers referenced by `include` directives,
defines macros as specified by `define` directives and prints values of symbolic constants.
Results are stored in `.const` files, one per arch.
For example, [sys/linux/tty.txt](/sys/linux/tty.txt) is translated into [sys/linux/tty_amd64.const](/sys/linux/tty_amd64.const).

The second step is generation of Go code for syzkaller.
This step uses syscall descriptions and the const files generated during the first step.
You can see a result in [sys/linux/gen/amd64.go](/sys/linux/gen/amd64.go) and in [executor/syscalls.h](/executor/syscalls.h).

## Describing new system calls

This section describes how to extend syzkaller to allow fuzz testing of a new system call;
this is particularly useful for kernel developers who are proposing new system calls.

First, add a declarative description of the new system call to the appropriate file:
 - Various `sys/linux/<subsystem>.txt` files hold system calls for particular kernel
   subsystems, for example `bpf` or `socket`.
 - [sys/linux/sys.txt](/sys/linux/sys.txt) holds descriptions for more general system calls.
 - An entirely new subsystem can be added as a new `sys/linux/<new>.txt` file.

The description of the syntax can be found [here](syscall_descriptions_syntax.md).

If the subsystem is present in the mainline kernel, run `make extract TARGETOS=linux SOURCEDIR=$KSRC`
with `$KSRC` set to the location of a kernel source tree. This will generate const files.
Not, that this will overwrite `.config` file you have in `$KSRC`.

If the subsystem is not present in the mainline kernel, then you need to manually run `syz-extract` binary:
```
make bin/syz-extract
bin/syz-extract -os linux -arch $ARCH -sourcedir "$LINUX" -builddir "$LINUXBLD" <new>.txt
```
`$ARCH` is one of `amd64`, `386` `arm64`, `arm`, `ppc64le`.
If the subsystem is supported on several architectures, then run `syz-extract` for each arch.
`$LINUX` should point to kernel source checkout, which is configured for the corresponding arch (i.e. you need to run `make someconfig && make` there first).
If the kernel was built into a separate directory (with `make O=...`) then also set `$LINUXBLD` to the location of the build directory.

Then, run `make generate` which will update generated code.

Rebuild syzkaller (`make clean all`) to force use of the new system call definitions.

Optionally, adjust the `enable_syscalls` configuration value for syzkaller to specifically target the new system calls.

In order to partially auto-generate system call descriptions you can use [headerparser](headerparser_usage.md).
