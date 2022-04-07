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
 - If the virtual machine reports that it has "Failed to start Raise network interfaces" or (which
   is a consequence of that) syzkaller is unable to connect to the virtual machines, try to disable
   the Predictable Network Interface Names mechanism. There are two ways to achieve this:
    - Add the following two lines to the kernel configuration file and recompile the kernel.
      ```
      CONFIG_CMDLINE_BOOL=y
      CONFIG_CMDLINE="net.ifnames=0"
      ```
    - Add the following line to the VM's properties inside the syzkaller manager configuration:
      ```
      "cmdline": "net.ifnames=0"
      ```

      The resulting configuration may look like this:
      ```json
      {
        "target": "linux/amd64",
        "http": "127.0.0.1:56741",
        "workdir": "$GOPATH/src/github.com/google/syzkaller/workdir",
        "kernel_obj": "$KERNEL",
        "image": "$IMAGE/stretch.img",
        "sshkey": "$IMAGE/stretch.id_rsa",
        "syzkaller": "$GOPATH/src/github.com/google/syzkaller",
        "procs": 8,
        "type": "qemu",
        "vm": {
            "count": 4,
            "kernel": "$KERNEL/arch/x86/boot/bzImage",
            "cmdline": "net.ifnames=0",
            "cpu": 2,
            "mem": 2048
        }
      }
      ```

      This is, however, not guaranteed to work across all virtualization technologies.

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
