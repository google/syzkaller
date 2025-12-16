# `syz-kfuzztest`

`syz-kfuzztest` is a standalone tool for fuzzing KFuzzTest targets from within
the kernel being fuzzed (e.g., a VM).

It is intended to be used for development-time fuzzing rather than continuous
fuzzing like `syz-manager`.

For more information on KFuzzTest, consult the [dedicated readme](kfuzztest.md)
or the Kernel documentation.

## Usage (in-VM fuzzing)

### Getting the Kernel Ready

It is important that the target Kernel image has the correct KConfig options
enabled. Namely

- `CONFIG_KFUZZTEST`
- `CONFIG_DEBUG_FS`
- `CONFIG_DEBUG_KERNEL`
- `CONFIG_KCOV`
- `CONFIG_DWARF4` or `CONFIG_DWARF5`
- `CONFIG_KASAN` _(optional, choose your favorite sanitizers for a better shot
  at finding bugs!)_

Furthermore, as you will need to connect to the VM being tested through SSH and
launch `syz-kfuzztest` _(a Go binary with LIBC dependencies)_, it is recommended
to create an image for the kernel being fuzzed (e.g., a Debian Trixie image).
Detailed instructions on how to do this can be found in
[this setup guide](linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md).

### Building and Launching the Binary

The `syz-kfuzztest` binary is built with `make syz-kfuzztest`, and is intended
to run on the Kernel fuzzed. The common case for this is within a VM _(after
all, the tool is trying to make the Kernel crash)_.

Then, ensure that the `syz-kfuzztest` binary and `vmlinux` image are copied
over into the VM. E.g.,

```sh
scp $KERNEL/vmlinux root@my-vm:~/syz-kfuzztest/vmlinux
scp $SYZKALLER/bin/syz-kfuzztest root@lmy-vm:~/syz-kfuzztest/syz-kfuzztest
```

Then launched like this:

```
usage: ./bin/syz-kfuzztest [flags] [enabled targets]

Args:
  One fuzz test name per enabled fuzz test arg. If empty, defaults to
  all discovered targets.
Example:
  ./syz-kfuzztest -vmlinux ~/kernel/vmlinux fuzz_target_0 fuzz_target_1
Flags:
  -display int
        Number of seconds between console outputs (default 5)
  -threads int
        Number of threads (default 2)
  -timeout int
        Timeout between program executions in seconds (default 0)
  -vmlinux string
        Path to vmlinux binary (default "vmlinux")
  -vv int
        verbosity
```

The enabled targets, which are listed after the flag arguments, are the names of
the enabled fuzz targets. For example given some KFuzzTest targets:

```c
FUZZ_TEST(kfuzztest_target_1, struct input_arg_type)
{
    /* ... */
}

FUZZ_TEST(kfuzztest_target_2, struct input_arg_type)
{
    /* ... */
}

```

Can be fuzzed with:

```bash
./syz-kfuzztest -vmlinux path/to/vmlinux -threads 4 kfuzztest_target_1 kfuzztest_target_2
```

If the enabled targets list is left empty, `syz-kfuzztest` will fuzz all
discovered targets in the kernel.

On exit, `syz-kfuzztest` will write the collected program counters (which are
collected with KCOV) into a file called `pcs.out`. These program counters can
be fed into [`syz-cover`](../tools/syz-cover/syz-cover.go) to generate an HTML
visualization of the lines that were covered during fuzzing. It is recommended
to do this on the host machine rather than the VM.

For example:

```sh
scp root@my-vm:~/syz-kfuzztest/pcs.out .
go run tools/syz-cover -config my.cfg pcs.out # May require the -force flag.
```
