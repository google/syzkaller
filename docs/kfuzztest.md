# KFuzzTest Integration With syzkaller

KFuzzTest, introduced initially in [this RFC](https://lore.kernel.org/all/20250813133812.926145-1-ethan.w.s.graham@gmail.com/)
is a framework for exposing internal kernel functions to a userspace fuzzing
engine like syzkaller. As the kernel docs put it:

> The Kernel Fuzz Testing Framework (KFuzzTest) is a framework designed to
> expose internal kernel functions to a userspace fuzzing engine.
>
> It is intended for testing stateless or low-state functions that are difficult
> to reach from the system call interface, such as routines involved in file
> format parsing or complex data transformations. This provides a method for
> in-situ fuzzing of kernel code without requiring that it be built as a
> separate userspace library or that its dependencies be stubbed out.

This document introduces how syzkaller integrates with KFuzzTest.

## Getting Started

Firstly, ensure that the KFuzzTest patch series has been applied to your Linux
tree.

As of the 26th of Semptember 2025, the most up-to-date version can be found in
[this Linux Kernel patch series](https://lore.kernel.org/all/20250919145750.3448393-1-ethan.w.s.graham@gmail.com/).

Once this is done, KFuzzTest targets can be defined on arbitrary kernel
functions using the `FUZZ_TEST` macro as described in the kernel docs in
`Documentation/dev-tools/kfuzztest.rst`.

### Configuration Options

Ensure that the following KConfig options are enabled for your kernel image:

- `CONFIG_DEBUG_FS` (used as a communication interface by KFuzzTest).
- `CONFIG_DEBUG_KERNEL`.
- `CONFIG_KFUZZTEST`.

It is also **highly** recommended to enable the following KConfig options for
more effective fuzzing.

- `CONFIG_KASAN` (catch memory bugs such as out-of-bounds-accesses).
- `CONFIG_KCOV` (to enable coverage guided fuzzing).

## Fuzzing KFuzzTest Targets

Syzkaller implements three ways to fuzz KFuzzTest targets:

1. `syz-manager` integration with static targets
2. `syz-manager` with dynamic targets
3. `syz-kfuzztest`: a standalone tool that runs inside a VM, discovers KFuzzTest
    targets dynamically, and fuzzes them.

### 1. `syz-manager` with static targets

Configuration for this method is identical to `syz-manager`, and is designed to
make it easy to integrate KFuzzTest fuzzing into existing continuous fuzzing
deployments.

One must first write a syzlang description for the KFuzzTest target(s) of
interest, for example in `/sys/linux/my_kfuzztest_target.txt`. Each target
should have the following format:

```
some_buffer {
        buf     ptr[inout, array[int8]]
        buflen  len[buf, int64]
}

kfuzztest_underflow_on_buffer(name ptr[in, string["test_underflow_on_buffer"]], data ptr[in, some_buffer], len bytesize[data], buf ptr[in, array[int8, 65536]]) (kfuzz_test)
```

Where:

- The first argument should be a string pointer to the name of the fuzz target,
  i.e,. the name of its `debugfs` input directory in the kernel.
- The second should be a pointer to a struct of the type that the fuzz
  target accepts as input.
- The third should be the size in bytes of the input argument.
- The call is annotated with attribute `kfuzz_test`.

The final `buf` argument is a buffer of size
`KFUZZTEST_MAX_INPUT_SIZE = 16 * PAGE_SIZE` and is used internally to ensure
that enough space is available in a program for the entire flattened input that
is sent into a KFuzzTest target.

For more information on writing syzkaller descriptions attributes, consult the
[syscall description](syscall_descriptions.md) and [syscall description syntax](syscall_descriptions_syntax.md)
documentation files.

To facilitate the tedious task of writing  `syz_kfuzztest_run` descriptions, a
tool (`tools/kfuzztest-gen`) is provided to automatically generate these from a
`vmlinux` binary. One can run the tool and paste the output into a syzlang file.

```sh
go run ./tools/kfuzztest-gen --vmlinux=path/to/vmlinux
```

After writing these descriptions to a file under the `/sys/linux/` directory
(for example, `/sys/linux/my_fuzz_targets.txt`), they need to be compiled with
`make descriptions`.

Finally, the targets can be enabled in `syz-manager` config file in the
`enable_syscalls` field, e.g.

```json
{
    "enable_syscalls": [ "syz_kfuzztest_run$test_underflow_on_buffer" ]
}
```

### 2. `syz-manager` with dynamic discovery

This feature greatly reduces the amount of setup needed for fuzzing KFuzzTest
targets, by discovering them all dynamically at launch.

This approach is considered less stable than the previous as it involves
generating descriptions for KFuzzTest targets without human input and then
immediately fuzzing them. It does, however, better reflect our intentions for
KFuzzTest: continuously fuzzing the kernel with a dynamically changing set of
targets with little intervention from syzkaller maintainers.

To enable this feature, configure the experimental `enable_kfuzztest` option in
the manager configuration, which enables all discovered KFuzzTest targets by
default.

```json
{
    "enable_kfuzztest": true
}
```

You must also enable pseudo-syscall `syz_kfuzztest_run`, like so:

```json
{
    "enable_syscalls": [
        "syz_kfuzztest_run"
    ],
}
```

**IMPORTANT:** for dynamic discovery to work, it is essential for the kernel
image pointed to by the manager configuration is built with `CONFIG_DWARF4` or
`CONFIG_DWARF5` enabled, as dynamic target discovery depends on these symbols
being emitted.

### 3. `syz-kfuzztest`, an in-VM standalone tool

In contrast with `syz-manager`, `syz-kfuzztest` is designed to perform coverage
guided fuzzing from within a VM directly rather than orchestrating a fleet of
VMs. It is primarily targetted at development-time fuzzing, rather than longterm
continuous fuzzing.

For more information, consult [the `syz-kfuzztest` documentation](syz-kfuzztest.md).
