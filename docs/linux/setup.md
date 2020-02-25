# How to set up syzkaller

Below are the generic instructions for how to set up syzkaller to fuzz the Linux kernel.
Instructions for a particular VM type or kernel arch can be found on these pages:

- [Setup: Ubuntu host, QEMU vm, x86-64 kernel](setup_ubuntu-host_qemu-vm_x86-64-kernel.md)
- [Setup: Ubuntu host, Odroid C2 board, arm64 kernel](setup_ubuntu-host_odroid-c2-board_arm64-kernel.md)
- [Setup: Linux host, QEMU vm, arm64 kernel](setup_linux-host_qemu-vm_arm64-kernel.md)
- [Setup: Linux host, QEMU vm, arm kernel](setup_linux-host_qemu-vm_arm-kernel.md)
- [Setup: Linux host, Android device, arm64 kernel](setup_linux-host_android-device_arm64-kernel.md)
- [Setup: Ubuntu host, Android device, arm32 kernel](setup_ubuntu-host_android-device_arm32-kernel.md)
- [Setup: Linux isolated host](setup_linux-host_isolated.md)

## Install

The following components are needed to use syzkaller:

 - C compiler with coverage support
 - Linux kernel with coverage additions
 - Virtual machine or a physical device
 - syzkaller itself

Generic steps to set up syzkaller are described below.

If you encounter any troubles, check the [troubleshooting](/docs/troubleshooting.md) page.

### C Compiler

Syzkaller is a coverage-guided fuzzer and therefore it needs the kernel to be built with coverage support, which requires a recent GCC version.
Coverage support was submitted to GCC, released in GCC 6.1.0 or later.

### Linux Kernel

Besides coverage support in GCC, you also need support for it on the kernel side.
KCOV was committed upstream in Linux kernel version 4.6 and can be enabled by configuring the kernel with `CONFIG_KCOV=y`.
For older kernels you need to backport commit [kernel: add kcov code coverage](https://github.com/torvalds/linux/commit/5c9a8750a6409c63a0f01d51a9024861022f6593).

To enable more syzkaller features and improve bug detection abilities, it's recommended to use additional config options.
See [this page](kernel_configs.md) for details.

### VM Setup

Syzkaller performs kernel fuzzing on slave virtual machines or physical devices.
These slave enviroments are referred to as VMs.
Out-of-the-box syzkaller supports QEMU, kvmtool and GCE virtual machines, Android devices and Odroid C2 boards.

These are the generic requirements for a syzkaller VM:

 - The fuzzing processes communicate with the outside world, so the VM image needs to include
   networking support.
 - The program files for the fuzzer processes are transmitted into the VM using SSH, so the VM image
   needs a running SSH server.
 - The VM's SSH configuration should be set up to allow root access for the identity that is
   included in the `syz-manager`'s configuration.  In other words, you should be able to do `ssh -i
   $SSHID -p $PORT root@localhost` without being prompted for a password (where `SSHID` is the SSH
   identification file and `PORT` is the port that are specified in the `syz-manager` configuration
   file).
 - The kernel exports coverage information via a debugfs entry, so the VM image needs to mount
   the debugfs filesystem at `/sys/kernel/debug`.

To use QEMU syzkaller VMs you have to install QEMU on your host system, see [QEMU docs](http://wiki.qemu.org/Manual) for details.
The [create-image.sh](/tools/create-image.sh) script can be used to create a suitable Linux image.
Detailed steps for setting up syzkaller with QEMU on a Linux host are avaialble for [x86-64](setup_ubuntu-host_qemu-vm_x86-64-kernel.md) and [arm64](setup_linux-host_qemu-vm_arm64-kernel.md) kernels.

For some details on fuzzing the kernel on an Android device check out [this page](setup_linux-host_android-device_arm64-kernel.md) and the explicit instructions for an Odroid C2 board are available [here](setup_ubuntu-host_odroid-c2-board_arm64-kernel.md).

### Syzkaller

`syzkaller` is written in [Go](https://golang.org), a `Go 1.11+` toolchain is required for build.
See [this](/docs/contributing.md#go) for instructions on how to install Go and build syzkaller.
