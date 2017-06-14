# Setup

## Install

The following components are needed to use syzkaller:

 - C compiler with coverage support
 - Linux kernel with coverage additions
 - Virtual machine or a physical device
 - syzkaller itself

Generic steps to set up syzkaller are described below.
More specific information (like the exact steps for a particular host system, VM type and a kernel architecture) can be found on the following pages:

- [Setup: Ubuntu host, QEMU vm, x86-64 kernel](docs/setup_ubuntu-host_qemu-vm_x86-64-kernel.md)
- [Setup: Ubuntu host, Odroid C2 board, arm64 kernel](docs/setup_ubuntu-host_odroid-c2-board_arm64-kernel.md)
- [Setup: Linux host, QEMU vm, arm64 kernel](docs/setup_linux-host_qemu-vm_arm64-kernel.md)
- [Setup: Linux host, Android device, arm64 kernel](docs/setup_linux-host_android-device_arm64-kernel.md)

If you encounter any troubles, check the [troubleshooting](troubleshooting.md) page.

### C Compiler

Syzkaller is a coverage-guided fuzzer and therefore it needs the kernel to be built with coverage support, which requires a recent GCC version.
Coverage support was submitted to GCC in revision `231296`, released in GCC v6.0.

### Linux Kernel

Besides coverage support in GCC, you also need support for it on the kernel side.
KCOV was committed upstream in Linux kernel version 4.6 and can be enabled by configuring the kernel with `CONFIG_KCOV=y`.
For older kernels you need to backport commit [kernel: add kcov code coverage](https://github.com/torvalds/linux/commit/5c9a8750a6409c63a0f01d51a9024861022f6593).

To enable more syzkaller features and improve bug detection abilities, it's recommended to use additional config options.
See [this page](linux_kernel_configs.md) for details.

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
The [create-image.sh](tools/create-image.sh) script can be used to create a suitable Linux image.
Detailed steps for setting up syzkaller with QEMU on a Linux host are avaialble for [x86-64](setup_ubuntu-host_qemu-vm_x86-64-kernel.md) and [arm64](setup_linux-host_qemu-vm_arm64-kernel.md) kernels.

For some details on fuzzing the kernel on an Android device check out [this page](setup_linux-host_android-device_arm64-kernel.md) and the explicit instructions for an Odroid C2 board are available [here](setup_ubuntu-host_odroid-c2-board_arm64-kernel.md).

### Syzkaller

The syzkaller tools are written in [Go](https://golang.org), so a Go compiler (>= 1.8) is needed
to build them.

Go distribution can be downloaded from https://golang.org/dl/.
Unpack Go into a directory, say, `$HOME/go`.
Then, set `GOROOT=$HOME/go` env var.
Then, add Go binaries to `PATH`, `PATH=$HOME/go/bin:$PATH`.
Then, set `GOPATH` env var to some empty dir, say `GOPATH=$HOME/gopath`.
Then, run `go get -u -d github.com/google/syzkaller/...` to checkout syzkaller sources with all dependencies.
Then, `cd $GOPATH/src/github.com/google/syzkaller` and
build with `make`, which generates compiled binaries in the `bin/` folder.

To build additional syzkaller tools run `make all-tools`.

## Configuration

The operation of the syzkaller `syz-manager` process is governed by a configuration file, passed at
invocation time with the `-config` option.  This configuration can be based on the
[example](syz-manager/config/testdata/qemu.cfg); the file is in JSON format with the
following keys in its top-level object:

 - `http`: URL that will display information about the running `syz-manager` process.
 - `workdir`: Location of a working directory for the `syz-manager` process. Outputs here include:
     - `<workdir>/crashes/*`: crash output files (see [Crash Reports](#crash-reports))
     - `<workdir>/corpus.db`: corpus with interesting programs
     - `<workdir>/instance-x`: per VM instance temporary files
 - `syzkaller`: Location of the `syzkaller` checkout.
 - `vmlinux`: Location of the `vmlinux` file that corresponds to the kernel being tested.
 - `procs`: Number of parallel test processes in each VM (4 or 8 would be a reasonable number).
 - `leak`: Detect memory leaks with kmemleak.
 - `image`: Location of the disk image file for the QEMU instance; a copy of this file is passed as the
   `-hda` option to `qemu-system-x86_64`.
 - `sandbox` : Sandboxing mode, the following modes are supported:
     - "none": don't do anything special (has false positives, e.g. due to killing init)
     - "setuid": impersonate into user nobody (65534), default
     - "namespace": use namespaces to drop privileges
       (requires a kernel built with `CONFIG_NAMESPACES`, `CONFIG_UTS_NS`,
       `CONFIG_USER_NS`, `CONFIG_PID_NS` and `CONFIG_NET_NS`)
 - `enable_syscalls`: List of syscalls to test (optional).
 - `disable_syscalls`: List of system calls that should be treated as disabled (optional).
 - `suppressions`: List of regexps for known bugs.
 - `type`: Type of virtual machine to use, e.g. `qemu` or `adb`.
 - `vm`: object with VM-type-specific parameters; for example, for `qemu` type paramters include:
     - `count`: Number of VMs to run in parallel.
     - `kernel`: Location of the `bzImage` file for the kernel to be tested;
       this is passed as the `-kernel` option to `qemu-system-x86_64`.
     - `cmdline`: Additional command line options for the booting kernel, for example `root=/dev/sda1`.
     - `sshkey`: Location (on the host machine) of an SSH identity to use for communicating with
       the virtual machine.
     - `cpu`: Number of CPUs to simulate in the VM (*not currently used*).
     - `mem`: Amount of memory (in MiB) for the VM; this is passed as the `-m` option to `qemu-system-x86_64`.

See also [config.go](syz-manager/config/config.go) for all config parameters.
