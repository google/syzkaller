# Troubleshooting

Here are some things to check if there are problems running syzkaller.

 - Check that QEMU can successfully boot the virtual machine.  For example,
   if `IMAGE` is set to the VM's disk image (as per the `image` config value)
   and `KERNEL` is set to the test kernel (as per the `kernel` config value)
   then something like the following command should start the VM successfully:

     ```shell
     qemu-system-x86_64 -hda $IMAGE -m 256 -net nic -net user,host=10.0.2.10,hostfwd=tcp::23505-:22 -enable-kvm -kernel $KERNEL -append root=/dev/sda
     ```

 - Check that inbound SSH to the running virtual machine works.  For example, with
   a VM running and with `SSHKEY` set to the SSH identity (as per the `sshkey` config value) the
   following command should connect:

     ```shell
     ssh -i $SSHKEY -p 23505 root@localhost
     ```

 - If you *are* having SSH difficulties, make sure your kernel configuration
   has networking enabled. Sometimes defconfig errs minimalistic and omits the
   following necessary options:
     ```shell
     CONFIG_VIRTIO_NET=y
     CONFIG_E1000=y
     CONFIG_E1000E=y
     ```

 - Check that the `CONFIG_KCOV` option is available inside the VM:
    - `ls /sys/kernel/debug       # Check debugfs mounted`
    - `ls /sys/kernel/debug/kcov  # Check kcov enabled`
    - Build the test program from `Documentation/kcov.txt` and run it inside the VM.

 - Check that debug information (from the `CONFIG_DEBUG_INFO` option) is available
    - Pass the hex output from the kcov test program to `addr2line -a -i -f -e $VMLINUX` (where
      `VMLINUX` is the vmlinux file, as per the `kernel_obj` config value), to confirm
      that symbols for the kernel are available.

Also see [this](/docs/troubleshooting.md) for generic troubleshooting advice.

If none of the above helps, file a bug on [the bug tracker](https://github.com/google/syzkaller/issues)
or ask us directly on the syzkaller@googlegroups.com mailing list.
Please include syzkaller commit id that you use and `syz-manager` output with `-debug` flag enabled if applicable.
