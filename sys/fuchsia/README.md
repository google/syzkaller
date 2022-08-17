# Fuchsia system call definitions

This directory contains the system call definitions for Fuchsia's kernel,
Zircon. They are currently updated manually, but we hope that will change Real
Soon Now. When/if it does, we'll update this file.

The `.fidl` files in the [vDSO
directory](https://cs.opensource.google/fuchsia/fuchsia/+/main:zircon/vdso/)
describe Zircon's system calls in FIDL, and in the comments there are English
and C++ descriptions. For every FIDL file, there should be a corresponding
`.txt` file in this directory that describes the system calls using [Syzkaller's
syzlang
language](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions_syntax.md).

Note that there must be a blank line between comments and the syzlang
declaration below it, or else Syzkaller will skip the declaration. For example,
do this:

```
# This function is great:

zx_great_function(handle zx_handle)
```

not this:

```
# This function is great:
zx_great_function(handle zx_handle)
```
