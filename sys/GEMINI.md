## Prerequisites

Syzkaller uses a special DSL called syzlang to express kernel interfaces.
Consult docs/syscall_descriptions.md and docs/syscall_descriptions_syntax.md
to learn more details.

The descriptions are located in sys/OS_NAME/ directories.
* Descriptions themselves are in .txt files.
* .txt.const files are generated from .txt files by running `make extract`.

## Writing descriptions for Linux

First ensure that you are given a path to a Linux kernel checkout.
We strive to write descriptions based on the latest linux-next tag.

When adding new syscalls and structures, try to follow the style
of existing descriptions. In particular, try to use existing types
and flags when possible.

First, find the definitions of syscalls and their arguments in the
kernel source code.
* DO NOT rely on the syscalls(7) man page, it is often outdated.
* DO NOT search for syscall definitions on the internet.
* DO grep kernel source code, especially the include/uapi folder.

Then, find the right file to add new descriptions. In many cases,
you will find such a file by looking at where related system calls
are described.
* IMPORTANT: DO NOT create new files unless absolutely necessary.
  Often, you can put the descriptions to more generic files.

For integer fields that look like bitmasks, try to find the flags
they could take and define them as flags in syzlang, listing all
possible const names. Note that sometimes you might have to add an
include directive. Look for inspiration to other .txt files in sys/linux.

For integer fields that look like file handles, try to find more details
about them and see whether they can be defined as resources. Try to find
existing resources in sys/linux/ that can be used, most likely they are
already there.

If the integer field is used for padding, ensure that you define it as const.

For other integer fields, explore how they are used in the Linux kernel source
code to see whether there are clear indications of the range of values they are
supposed to take.

## Struct Packing

Always check the struct definition in the Linux kernel headers:
* If the kernel struct has `__packed` or `__attribute__((packed))` or
  `__attribute__((__packed__))`, the syzlang struct MUST be marked `[packed]`
  at the closing brace (e.g. `foo { ... } [packed]`). Without `[packed]`,
  syzkaller applies natural alignment padding (e.g. inserting padding after
  `int8` before `int16`/`int32`/`int64`), causing field offsets to diverge
  from the kernel.
* If the kernel struct is NOT `__packed`, DO NOT mark it `[packed]` in
  syzlang, as this would eliminate natural alignment padding expected by
  the kernel.
* If individual struct fields have explicit alignment attributes (e.g.
  `__attribute__((aligned(N)))`), define explicit const padding fields of the
  appropriate size (the difference required to align the field to the N-byte boundary)
  to match the alignment.

## Flexible and Variable-Length Arrays

When a kernel struct ends with a flexible or zero-length array (such as
`type member[];`, `type member[0];`, or legacy `type member[1];`):
* Declare the field in syzlang as a dynamic array: `member array[type]`.
* Pair the array with its corresponding length or count field in the struct
  using `len[member, intX]` (e.g. `num_elems len[elems, int32]`).
* DO NOT hardcode flexible array members as fixed-size arrays (e.g.,
  `array[int8, 32]`) unless the kernel explicitly requires a fixed size,
  as this prevents syzkaller from fuzzing variable lengths.
* DO NOT omit trailing flexible array members (e.g., capability blocks or
  payload buffers).

## Socket Options and Ioctls

When describing socket options and ioctls:
* In `getsockopt`, the length argument is a bidirectional `socklen_t *`
  (`int32`). Always define `optlen` as `ptr[inout, len[optval, int32]]`.
  DO NOT use `ptr[in, ...]` (the kernel writes to it) and DO NOT use `intptr`
  (`socklen_t` is 32-bit).
* In `setsockopt`, the length argument is passed by value: `len[optval, int32]`.
* For ioctl commands, check the macro definition in kernel headers:
  * `_IOR`: Kernel writes data to userspace. Use `ptr[out, ...]` (or `buffer[out]`).
  * `_IOW`: Kernel reads data from userspace. Use `ptr[in, ...]`.
  * `_IOWR`: Bidirectional. Use `ptr[inout, ...]`.
  * `_IO`: The command takes a scalar integer argument (or no argument). Pass
    scalar integer types (e.g. `intptr`, `flags[...]`, or `const[0]`), NOT a pointer
    `ptr[...]`, unless the driver specifically takes a pointer under `_IO` (e.g. VFIO).

After adding descriptions, you should run `make extract` to extract
the newly introduced constants into the `sys/linux/` directory.

It should only be run on latest `linux-next` tag this way:
`$ CI=true ./tools/syz-env make extract SOURCEDIR=$PATH_TO_LINUX_CHECKOUT`

If `make extract` fails, it might indicate that you are missing some includes.

At the end, help the user review the results by indicating the locations
in the Linux kernel source code where the new syscalls and structures
were found.

## Testing

Then, run `make generate` to verify that the descriptions are correct.

Also, do not forget to run `make format` to ensure that the descriptions
are formatted correctly.

You can also run `syz-check` against a built Linux kernel object file (`vmlinux`)
with DWARF debug info to statically verify descriptions:
`$ go run ./tools/syz-check -obj-amd64 $PATH_TO_VMLINUX`

This will cross-reference struct sizes, field offsets, alignments, and bitfield
layouts against DWARF and report warnings.

Remember that these commands must be run inside of the syzkaller checkout.
