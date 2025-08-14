# KFuzzTest Integration With syzkaller

## Getting Started

Firstly, ensure that the KFuzzTest patch series has been applied to your Linux
tree.

As of the 12th of August 2025, the most up-to-date version can be found in
[this pull request](https://github.com/ethangraham2001/linux/pull/12).

Once this is done, KFuzzTest targets can be defined on arbitrary kernel
functions using the `FUZZ_TEST` macro as described in the kernel docs in
`Documentation/dev-tools/kfuzztest.rst`.

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
interest, for example in `/sys/linux/kfuzztest.txt`. Each target should be
named `syz_kfuzztest_run$<target-name>`, and have the following format:

```
some_buffer {
        buf     ptr[inout, array[int8]]
        buflen  len[buf, int64]
}

syz_kfuzztest_run$test_underflow_on_buffer(name ptr[in, string["test_underflow_on_buffer"]], data ptr[in, some_buffer], len bytesize[data])
```

Where:

- The first argument should be a string pointer to the name of the fuzz target,
  i.e,. the name of its `debugfs` input directory in the kernel.
- The second should be a pointer to a struct of the type that the fuzz 
  target accepts as input.
- The third should be the size in bytes of the input argument.

To facilitate the tedious task of writing  `syz_kfuzztest_run` descriptions, a
tool (`tools/kfuzztest-gen`) is provided to automatically generate these from a
`vmlinux` binary. One can run the tool and paste the output into a syzlang file.

```sh
go run ./tools/kfuzztest-gen --vmlinux=path/to/vmlinux
```

Since these descriptions are built alongside all other syzlang descriptions,
the one should re-run `make` after generating them.

Finally, the targets can be enabled in `syz-manager` config file in the
`enable_syscalls` field, e.g.

```json
{
    "enable_syscalls": [ "syz_kfuzztest_run$test_underflow_on_buffer" ]
}
```

### 2. `syz-manager` with dynamic discovery

This experimental feature greatly reduces the amount of setup needed for fuzzing
KFuzzTest targets, by discovering them all dynamically at launch.

This approach is considered less stable than the previous appraoch as it
involves generating descriptions for KFuzzTest targets without human input and
then immediately fuzzing them. It does, however, better reflect our intentions
for KFuzzTest: continuously fuzzing the kernel with a dynamically changing set
of targets with little intervention from syzkaller maintainers.

To enable this feature, configure the experimental `enable_kfuzztest` option in
the manager configuration, which enables all discovered KFuzzTest targets by
default.

```json
{
    "enable_kfuzztest": true
}
```

### 3. `syz-kfuzztest`, an in-VM standalone tool

In contrast with `syz-manager`, `syz-kfuzztest` is designed to perform coverage
guided fuzzing from within a VM directly rather than orchestrating a fleet of
VMs. All targets are discovered dynamically.

The `syz-kfuzztest` executable is built automatically by `make`.

```
Usage of ./bin/syz-kfuzztest:
  -display int
        Display interval (default 5)
  -display-progs
        Display last executed prog for each target
  -enable value
        Enables a KFuzzTest target. When empty, enables all KFuzzTest targets
  -extract-only
        Extract KFuzzTest targets from vmlinux and display their descriptions
  -threads int
        Number of threads (default 1)
  -timeout int
        Timeout in milliseconds
  -vmlinux string
        Path to vmlinux binary
  -vv int
        verbosity
```

To run it in a VM the user must also ensure that the `vmlinux` of the running
kernel is also available, and pointed to by the `-vmlinux` flag.
