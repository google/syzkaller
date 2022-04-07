# Troubleshooting

Here are some things to check if there are problems running syzkaller.

 - Use the `-debug` command line option to make syzkaller print all possible debug output,
   from both the `syz-manager` top-level program and the `syz-fuzzer` instances. With this option
   syzkaller will only run one VM instance.

 - Use the `-vv N` command line option to increase the amount of logging output, from both
   the `syz-manager` top-level program and the `syz-fuzzer` instances (which go to the
   output files in the `crashes` subdirectory of the working directory). Higher values of
   N give more output.

 - If logging indicates problems with the executor program (e.g. `executor failure`),
   try manually running a short sequence of system calls:
     - Copy `syz-executor` and `syz-execprog` into a running VM.
     - In the VM run `./syz-execprog -executor ./syz-executor -debug sampleprog` where
       sampleprog is a simple system call script (e.g. just containing `getpid()`).
     - For example, if this reports that `clone` has failed, this probably indicates
       that the test kernel does not include support for all of the required namespaces.
       In this case, running the `syz-execprog` test with the `-sandbox=setuid` option fixes the problem,
       so the main configuration needs to be updated to set `sandbox` to `setuid`.

Also see [this](linux/troubleshooting.md) for Linux kernel specific troubleshooting advice.

If none of the above helps, file a bug on [the bug tracker](https://github.com/google/syzkaller/issues)
or ask us directly on the syzkaller@googlegroups.com mailing list.
Please include syzkaller commit id that you use and `syz-manager` output with `-debug` flag enabled if applicable.
