# Syscall descriptions

`syzkaller` uses declarative description of syscall interfaces to manipulate
programs (sequences of syscalls). Below you can see (hopefully self-explanatory)
excerpt from the descriptions:

```
open(file filename, flags flags[open_flags], mode flags[open_mode]) fd
read(fd fd, buf buffer[out], count len[buf])
close(fd fd)
open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
```

The descriptions are contained in `sys/$OS/*.txt` files.
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

There is also another [binary representation](/prog/decodeexec.go)
of the programs (called `exec`), that is much simpler, does not contains rich type information (irreversible)
and is used for actual execution (interpretation) of programs by [executor](/executor/executor.cc).

## Describing new system calls

This section describes how to extend syzkaller to allow fuzz testing of more kernel interfaces.
This is particularly useful for kernel developers who are proposing new system calls.

Currently all syscall descriptions are manually-written. There is an
[open issue](https://github.com/google/syzkaller/issues/590) to provide some aid
for this process and some ongoing work, but we are not there yet to have a
fully-automated way to generate descriptions.
There is a helper [headerparser](headerparser_usage.md) utility that can auto-generate
some parts of descriptions from header files.

To enable fuzzing of a new kernel interface:

1. Study the interface, find out which syscalls are required to use it. Sometimes there is nothing besides the source code, but here are some things that may help:

   - Searching the Internet for the interface name and/or some unique constants.
   - Grepping Documentation/ dir in the kernel.
   - Searching tools/testing/ dir in the kernel.
   - Looking for large comment blocks in the source code.
   - Finding commit that added the interface via `git blame` or `git log` and reading the commit description.
   - Reading source code of or tracing libraries or applications that are known to use this interface.

2. Using [syntax documentation](syscall_descriptions_syntax.md) and
   [existing descriptions](/sys/linux/) as an example, add a declarative
   description of this interface to the appropriate file:

    - `sys/linux/<subsystem>.txt` files hold system calls for particular kernel
      subsystems, for example [bpf.txt](/sys/linux/bpf.txt) or [socket.txt](/sys/linux/socket.txt).
    - [sys/linux/sys.txt](/sys/linux/sys.txt) holds descriptions for more general system calls.
    - An entirely new subsystem can be added as a new `sys/linux/<new>.txt` file.
    - If subsystem descriptions are split across multiple files, prefix the name of each file with the name of the subsystem (e.g. use `dev_*.txt` for descriptions of `/dev/` devices, use `socket_*.txt` for sockets, etc).

3. After adding/changing descriptions run:

    ``` bash
    make extract TARGETOS=linux SOURCEDIR=$KSRC
    make generate
    make
    ```

4. Run syzkaller. Make sure that the newly added interface in being reached by
   syzkaller using the [coverage](coverage.md) information page.

In the instructions above `make extract` generates/updates the `*.const` files.
`$KSRC` should point to the _latest_ kernel checkout.\
_Note_: for Linux the _latest_ kernel checkout generally means the
[mainline](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/) tree.\
However, in some cases we add descriptions for interfaces that are not in the mainline tree yet,
so if `make extract` complains about missing header files or constants undefined on all architectures,
try to use the latest [linux-next](https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/log/)
tree (or if it happens to be broken at the moment, try a slightly older linux-next tree).\
_Note_: `make extract` overwrites `.config` in `$KSRC` and `mrproper`'s it.
_Note_: `*.const` files are checked-in with the `*.txt` changes in the same commit.

Then `make generate` updates generated code and `make` rebuilds binaries.\
Note: `make generate` does not require any kernel sources, native compilers, etc
and is pure text processing.
Note: `make generate` also updates the SYZ_REVISION under `executor/defs.h`, which
is required for machine check while running syz-manager. This should be taken care
of especially if you are trying to rebase with your own change on syscall description.

Note: `make extract` extracts constants for all architectures which requires
installed cross-compilers. If you get errors about missing compilers/libraries,
try `sudo make install_prerequisites` or install equivalent package for your distro.
Note: `sudo make install_prerequisites` will success even with some package failed to
install, `sudo apt-get update && sudo apt-get upgrade` might be required to make this
more efficient.

If you want to fuzz only the new subsystem that you described locally, you may
find the `enable_syscalls` configuration parameter useful to specifically target
the new system calls. All system calls in the `enable_syscalls` list
will be enabled if their requirements are met (ie. if they are supported
in the target machine and any other system calls that need to run in
order to provide inputs for them are also enabled). You can also include
wildcard definitions to enable multiple system calls in a single line,
for example: `"ioctl"` will enable all the described ioctls syscalls
that have their requirements met, ``"ioctl$UDMABUF_CREATE"`` enables
only that particular ioctl call, ``"write$UHID_*"`` enables all write
system calls that start with that description identifier.

When updating existing syzkaller descriptions, note, that unless there's a drastic
change in descriptions for a particular syscall, the programs that are already in
the corpus will be kept there, unless you manually clear them out (for example by
removing the `corpus.db` file).

<div id="tips"/>

## Description tips and FAQ

<div id="names"/>

### Syscall, struct, field, flags names

Stick with existing kernel names for things, don't invent new names if possible.

Following established naming conventions provides the following benefits:
(1) consistency and familiarity of names used across kernel interfaces,
which also enables searching kernel sources for related names; and
(2) enable static checking of descriptions (e.g. missed flags or mistyped fields)
with [syz-check](/tools/syz-check/check.go).

For example, if there is an existing enum `v4l2_buf_type` in the kernel headers,
use this name for flags in descriptions as well. The same for structs, unions,
fields, etc. For syscall variants, use the command name after the `$` sign.
For example, `fcntl$F_GET_RW_HINT`, `ioctl$FIOCLEX`, `setsockopt$SO_TIMESTAMP`.

If you need to describe several variants of the same kernel struct, the naming
convention understood by `syz-check` is `<ORIGINAL_KERNEL_NAME>_some_suffix`.

<div id="ordering"/>

### Resources for syscall ordering

Resources and resource directions (`in`, `out`, `inout`) impose implicit ordering
constraints on involved syscalls.

If a syscall accepts a resource of a particular type (e.g. has `fd_cdrom` as an input),
then it will be generally placed after a syscall that has this resource as output,
so that the resource value can be passed between syscalls. For example:

```
r0 = openat$cdrom(...)
ioctl$CDROMPAUSE(r0, 0x123)
close(r0)
```

Syscall arguments are always `in`, return values are `out` and pointer indirections
have explicit direction as `ptr` type attribute. Also, it is possible to specify
direction attribute individually for struct fields to account for more complex 
producer/consumer scenarious with structs that include both input/output resources.

<div id="values"/>

### Use of unexpected/undeclared values

When specifying integer/string flags or integer fields stick with the official expected values only.

Commonly, bugs are triggered by unexpected inputs. With that in mind, it can be too tempting to introduce
some unexpected values to descriptions (e.g. `-1` or `INT_MAX`). This is not encouraged for several reasons.
First, this is a cross-cutting aspect and these special unexpected values are applicable to just
any flags and integer fields. Manually specifying them thousands of times is not scalable and
is not maintainable. Second, It's hard for the fuzzer to come up with correct complex syscall sequences,
and the descriptions are meant to help with this. Coming up with unexpected integer values is easy
and the fuzzer does not need help here. Overall the idea is to improve the generic fuzzer logic
to handle these cases better, which will help all descriptions, rather than over-specializing each
individual integer separately. Fuzzer already has several tricks to deal with this, e.g. comparison
operand value interception and list of typical magic values.

Note: some values for flags may be undocumented only as an oversight. These values should be added to descriptions.

<div id="flags"/>

### Flags/enums

The `flags` type is used for all of:

 - sets of mutually exclusive values, where only one of them should be chosen (like C enum);
 - sets of bit flags, where multiple values can be combined with bitwise OR (like mmap flags);
 - any combination of the above.

The fuzzer has logic to distinguish enums and bit flags, and generates values
accordingly. So the general guideline is just to enumerate the meaningful values
in `flags` without adding any "special" values to "help" the current fuzzer logic.
When/if the fuzzer logic changes/improves, these manual additions may become
unnecessary, or, worse, interfere with the fuzzer ability to generate good values.

## Description compilation internals

The process of compiling the textual syscall descriptions into machine-usable
form used by `syzkaller` to actually generate programs consists of 2 steps.

The first step is extraction of values of symbolic constants from kernel sources using
[syz-extract](/sys/syz-extract) utility. `syz-extract` generates a small C program that
includes kernel headers referenced by `include` directives, defines macros as specified
by `define` directives and prints values of symbolic constants.
Results are stored in `.const` files, one per arch.
For example, [sys/linux/dev_ptmx.txt](/sys/linux/dev_ptmx.txt) is translated into
[sys/linux/dev_ptmx.txt.const](/sys/linux/dev_ptmx.txt.const).

The second step is translation of descriptions into Go code using
[syz-sysgen](/sys/syz-sysgen) utility (the actual compiler code lives in
[pkg/ast](/pkg/ast/) and [pkg/compiler](/pkg/compiler/)).
This step uses syscall descriptions and the const files generated during the first step
and produces instantiations of `Syscall` and `Type` types defined in [prog/types.go](/prog/types.go).
You can see an example of the compiler output for Akaros in `sys/akaros/gen/amd64.go`.
This step also generates some minimal syscall metadata for C++ code in `executor/syscalls.h`.

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

<div id="testing"/>

### Testing of descriptions

Descriptions themselves may contain bugs. After running `syz-manager` with the new descriptions
it's always useful to check the kernel code coverage report available in the `syz-manager` web UI.
The report allows to assess if everything one expects to be covered is in fact covered,
and if not, where the fuzzer gets stuck. However, this is a useful but quite indirect assessment
of the descriptions correctness. The fuzzer may get around some bugs in the descriptions by diverging
from what the descriptions say, but it makes it considerably harder for the fuzzer to progress.

Tests stored in `sys/OS/test/*` provide a more direct testing of the descriptions. Each test is just
a program with checked syscall return values. The syntax of the programs is not currently documented,
but look at the [existing examples](/sys/linux/test) and at the program [deserialization code](/prog/encoding.go).
`AUTO` keyword can be used as a value for consts and pointers, for pointers it will lead to
some reasonable sequential allocation of memory addresses.

It's always good to add a test at least for "the main successful scenario" for the subsystem.
It will ensure that the descriptions are actually correct and that it's possible for the fuzzer
to come up with the successful scenario. See [io_uring test](/sys/linux/test/io_uring) as a good example.

The tests can be run with the `syz-runtest` utility as:
```
make runtest && bin/syz-runtest -config manager.config
```
`syz-runtest` boots multiple VMs and runs these tests in different execution modes inside of the VMs.

However, full `syz-runtest` run takes time, so while developing the test, it's more handy to run it
using the `syz-execprog` utility. To run the test, copy `syz-execprog`, `syz-executor` and the test
into a manually booted VM and then run the following command inside of the VM:
```
syz-execprog -debug -threaded=0 mytest
```
It will show results of all executed syscalls. It's also handy for manual debugging of pseudo-syscall code:
if you add some temporal `debug` calls to the pseudo-syscall, `syz-execprog -debug` will show their output.

The test syntax can be checked by running:
```
go test -run=TestSysTests ./pkg/csource
```
