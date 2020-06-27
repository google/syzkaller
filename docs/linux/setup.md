# How to set up syzkaller

Generic instructions on how to set up Linux kernel fuzzing with syzkaller are [below](setup.md#install).

Instructions for a particular VM type or kernel architecture can be found on these pages:

- [Setup: Ubuntu host, QEMU vm, x86-64 kernel](setup_ubuntu-host_qemu-vm_x86-64-kernel.md)
- [Setup: Linux host, QEMU vm, arm64 kernel](setup_linux-host_qemu-vm_arm64-kernel.md)
- [Setup: Linux host, QEMU vm, arm kernel](setup_linux-host_qemu-vm_arm-kernel.md)
- [Setup: Linux host, QEMU vm, riscv64 kernel](setup_linux-host_qemu-vm_riscv64-kernel.md)
- [Setup: Linux host, Android device, arm32/64 kernel](setup_linux-host_android-device_arm-kernel.md)
- [Setup: Linux isolated host](setup_linux-host_isolated.md)
- [Setup: Ubuntu host, Odroid C2 board, arm64 kernel](setup_ubuntu-host_odroid-c2-board_arm64-kernel.md) [outdated]

## Install

The following components are needed to use syzkaller:

 - Go compiler and syzkaller itself
 - C compiler with coverage support
 - Linux kernel with coverage additions
 - Virtual machine or a physical device

If you encounter any troubles, check the [troubleshooting](/docs/troubleshooting.md) page.

### Go and syzkaller

`syzkaller` is written in [Go](https://golang.org), and `Go 1.13+`
toolchain is required for build. The toolchain can be installed with:

```
wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
tar -xf go1.14.2.linux-amd64.tar.gz
mv go goroot
mkdir gopath
export GOPATH=`pwd`/gopath
export GOROOT=`pwd`/goroot
export PATH=$GOPATH/bin:$PATH
export PATH=$GOROOT/bin:$PATH
```

To download and build `syzkaller`:

``` bash
go get -u -d github.com/google/syzkaller/prog
cd gopath/src/github.com/google/syzkaller/
make
```

As the result compiled binaries should appear in the `bin/` dir.

Also see [Go Getting Started](https://golang.org/doc/install) for more details.

Note: if you want to do cross-OS/arch testing, you need to specify `TARGETOS`,
`TARGETVMARCH` and `TARGETARCH` arguments to `make`. See the [Makefile](/Makefile) for details.

Note: older versions of Go toolchain formatted code in a slightly
[different way](https://github.com/golang/go/issues/25161).
So if you are seeing unrelated code formatting diffs after running `make generate`
or `make format`, you may be using `Go 1.10` or older. In such case update to `Go 1.13+`.

### Environment

You might need to properly setup `binutils` if you're fuzzing in a cross-arch environment as described [here](coverage.md#binutils).

### C Compiler

Syzkaller is a coverage-guided fuzzer and therefore it needs the kernel to be built with coverage support, which requires a recent GCC version.
Coverage support was submitted to GCC, released in GCC 6.1.0 or later.
Make sure that your GCC meets this requirement, or get a GCC that [syzbot](/docs/syzbot.md) uses [here](/docs/syzbot.md#crash-does-not-reproduce).

### Linux Kernel

Besides coverage support in GCC, you also need support for it on the kernel side.
KCOV was added into mainline Linux kernel in version 4.6 and is be enabled by `CONFIG_KCOV=y` kernel configation option.
For older kernels you need to at least backport commit [kernel: add kcov code coverage](https://github.com/torvalds/linux/commit/5c9a8750a6409c63a0f01d51a9024861022f6593).
Besides that, it's recomended to backport all kernel patches that touch `kernel/kcov.c`.

To enable more syzkaller features and improve bug detection abilities, it's recommended to use additional config options.
See [this page](kernel_configs.md) for details.

### VM Setup

Syzkaller performs kernel fuzzing on worker virtual machines or physical devices.
These worker enviroments are referred to as VMs.
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

See the links at the top of the document for instructions on setting up syzkaller for QEMU, Android and some other types of VMs.

### Troubleshooting

* QEMU requires root for `-enable-kvm`.

    Solution: add your user to the `kvm` group (`sudo usermod -a -G kvm` and relogin).

* QEMU crashes with:

    ```
    qemu-system-x86_64: error: failed to set MSR 0x48b to 0x159ff00000000
    qemu-system-x86_64: /build/qemu-EmNSP4/qemu-4.2/target/i386/kvm.c:2947: kvm_put_msrs: Assertion `ret == cpu->kvm_msr_buf->nmsrs' failed.
   ```

    Solution: remove `-cpu host,migratable=off` from the QEMU command line. The easiest way to do that is to set `qemu_args` to `-enable-kvm` in the `syz-manager` config file.
