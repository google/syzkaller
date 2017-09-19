# Troubleshooting

Here are some things to check if there are problems running syzkaller.

 - Check that QEMU can successfully boot the virtual machine.  For example,
   if `IMAGE` is set to the VM's disk image (as per the `image` config value)
   and `KERNEL` is set to the test kernel (as per the `kernel` config value)
   then something like the following command should start the VM successfully:

       ```qemu-system-x86_64 -hda $IMAGE -m 256 -net nic -net user,host=10.0.2.10,hostfwd=tcp::23505-:22 -enable-kvm -kernel $KERNEL -append root=/dev/sda```

 - Check that inbound SSH to the running virtual machine works.  For example, with
   a VM running and with `SSHKEY` set to the SSH identity (as per the `sshkey` config value) the
   following command should connect:

       ```ssh -i $SSHKEY -p 23505 root@localhost```

 - Check that the `CONFIG_KCOV` option is available inside the VM:
    - `ls /sys/kernel/debug       # Check debugfs mounted`
    - `ls /sys/kernel/debug/kcov  # Check kcov enabled`
    - Build the test program from `Documentation/kcov.txt` and run it inside the VM.

 - Check that debug information (from the `CONFIG_DEBUG_INFO` option) is available
    - Pass the hex output from the kcov test program to `addr2line -a -i -f -e $VMLINUX` (where
      `VMLINUX` is the vmlinux file, as per the `vmlinux` config value), to confirm
      that symbols for the kernel are available.

 - Use the `-debug` command line option to make syzkaller print all possible debug output,
   from both the `syz-manager` top-level program and the `syz-fuzzer` instances. With this option
   syzkaller will only run one VM instance.

 - Use the `-v N` command line option to increase the amount of logging output, from both
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

If none of the above helps, file a bug on [the bug tracker](https://github.com/google/syzkaller/issues)
or ask us directly on the syzkaller@googlegroups.com mailing list.
Please include syzkaller commit id that you use and `syz-manager` output with `-debug` flag enabled if applicable.
