# FreeBSD

This page contains instructions to set up syzkaller to run on a FreeBSD or Linux host and fuzz an amd64 FreeBSD kernel running in a virtual machine.

Currently, syzkaller can fuzz FreeBSD running under bhyve, QEMU or GCE (Google Compute Engine).  Regardless of the mode of operation, some common steps must be followed.

## Setting up a host

`syz-manager` is the component of syzkaller that manages target VMs.  It runs on a host system and automatically creates, runs and destroys VMs which share a user-specified image file.

### Setting up a FreeBSD host

To build syzkaller out of the box, a recent version of FreeBSD 13.0-CURRENT must be used for the host.  Older versions of FreeBSD can be used but will require manual tweaking.

The required dependencies can be installed by running:
```console
# pkg install bash gcc git gmake go golangci-lint llvm
```
When using bhyve as the VM backend, a DHCP server must also be installed:
```console
# pkg install dnsmasq
```
To checkout the syzkaller sources, run:
```console
$ git clone https://github.com/google/syzkaller
```
and the binaries can be built by running:
```console
$ cd syzkaller
$ gmake
```

Once this completes, a `syz-manager` executable should be available under `bin/`.

### Setting up a Linux host

On an `amd64` Linux host, you can cross-compile FreeBSD userspace binaries (`syz-executor`, C reproducers) and build FreeBSD `amd64` kernels without a separate FreeBSD host machine.

Prerequisites on Debian/Ubuntu: `clang`, `lld`, `llvm`, `cpp`, `qemu-system-x86`, `openssh-client`, `expect`, `curl`, `xz-utils`, and `/dev/kvm` access.

1. Prepare a base FreeBSD VM image (`userspace/image` + `userspace/key`) and userspace sysroot (`sysroot/`) from official FreeBSD snapshots:
```console
$ ./tools/create-freebsd-image.sh -o ~/freebsd-env
```
Pass `-k` if you want a keyless/passwordless VM image (for example, to use as a reusable QEMU `builder_image`), and `-S` to skip extracting `sysroot/`.

2. Build host binaries (`syz-manager`, `syz-repro`, etc.) and cross-compile FreeBSD target binaries (`syz-execprog`, `syz-executor`) using the extracted sysroot (`SOURCEDIR_FREEBSD` or `SOURCEDIR`):
```console
$ export SOURCEDIR_FREEBSD=~/freebsd-env/sysroot
$ make host target TARGETOS=freebsd TARGETARCH=amd64
```

3. Build a `SYZKALLER` FreeBSD kernel (`KCOV` + `KASAN` + `COVERAGE`) and install it into a bootable VM image inside an isolated ephemeral QEMU VM:
```console
$ git clone --depth=1 --branch=main https://github.com/freebsd/freebsd-src.git ~/freebsd-src
$ make syz-build
$ mkdir -p ~/freebsd-build && cd ~/freebsd-build
$ /path/to/syzkaller/bin/syz-build \
	-os freebsd -arch amd64 -vm qemu \
	-kernel_src ~/freebsd-src \
	-userspace ~/freebsd-env/userspace \
	-trace
```
This produces `~/freebsd-build/image`, `~/freebsd-build/key` (if present in `userspace`), `~/freebsd-build/kernel.config`, and `~/freebsd-build/obj/kernel.full` (used by `syz-manager` via `"kernel_obj": "~/freebsd-build/obj"` and `"kernel_src": "~/freebsd-src"`).

For `syz-ci` on a Linux host (e.g. targeting GCE or QEMU where `userspace/image` may not carry a prebaked SSH key), create a keyless builder image once with `./tools/create-freebsd-image.sh -k -S -o ~/freebsd-builder` and set `"kernel_builder_image"` in the manager config (or pass `-builder_image` to `bin/syz-build`):
```json
	"kernel_builder_image": "/path/to/freebsd-builder/userspace/image"
```

Requirements for the `syz-ci` host itself:
- `clang`, `lld`, `llvm`, `cpp` and `qemu-system-x86` must be installed, and the `syz-ci` process must have access to `/dev/kvm` (the kernel is built inside a local KVM-accelerated QEMU VM requiring 8 GiB of available RAM and up to 16 vCPUs).
- `SOURCEDIR_FREEBSD` must be set in the environment of the `syz-ci` process (e.g. in its systemd unit), otherwise `syz-ci` refuses to start since it cannot build `syz-executor` for the target.
- Infrastructure failures of the build VM (QEMU/KVM/SSH problems, disk setup, packaging of the results) are classified as `build.InfraError` and are not reported to the dashboard as kernel build errors; only failures of the kernel toolchain/kernel build steps inside the VM are.

**Warning:** images created with `-k` have an empty root password and must only be used as a local QEMU `kernel_builder_image` (where the VM has no network access). Never use them as a fuzzing `userspace/image` on GCE or any other network-reachable VM.

## Setting up the FreeBSD VM

It is easiest to start with a [snapshot image](https://ftp.freebsd.org/pub/FreeBSD/snapshots/VM-IMAGES/14.0-CURRENT/amd64/Latest/) of FreeBSD.  Fetch a QCOW2 disk image for QEMU or a raw image for GCE or bhyve.
Fetch a copy of the FreeBSD kernel sources and place them in `/usr/src`. You will likely need to expand the disk of the VM. Before booting the VM, run:
```console
# truncate -s 15G $IMAGEFILE
```
To enable KCOV on FreeBSD, a custom kernel must be compiled. It is easiest to do this on the host.<br>
Before booting the VM, compile a custom kernel on the host and install it on the VM. On the host:
```console
# mdconfig -a -f $IMAGEFILE
# mount /dev/md0p4 /mnt
```
This will create a memory device for the VM file and allow host to install the custom kernel source on the VM. <br>
To get a copy of the current development sources:
```console
# pkg install git
# git clone --depth=1 --branch=main https://github.com/freebsd/freebsd-src /usr/src
```
To create a custom kernel configuration file for syzkaller and build a new kernel, run:

```console
# cd /usr/src/sys/amd64/conf
# cat <<__EOF__ > SYZKALLER
include "./GENERIC"

ident	SYZKALLER

options 	COVERAGE
options 	KCOV
__EOF__
# cd /usr/src
# make -j $(sysctl -n hw.ncpu) KERNCONF=SYZKALLER buildkernel
# make KERNCONF=SYZKALLER installkernel DESTDIR=/mnt
```
Before booting the VM, make sure to run:
```console
# umount /mnt
```
The md device will linger and you can use it again later if you want. Otherwise destroy it:
```console
# mdconfig -d -u 0
```
Use QEMU to start a VM using the downloaded image:

```console
$ qemu-system-x86_64 -hda $IMAGEFILE -nographic -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 -net nic,model=e1000
```
When the boot loader menu is printed, escape to the loader prompt and enter the commands `set console="comconsole"` and `boot`.  Once you reach a login prompt, log in as root and add a couple of configuration parameters to `/boot/loader.conf`:

```console
# cat <<__EOF__ >>/boot/loader.conf
autoboot_delay="-1"
console="comconsole"
__EOF__
```
After VM is booted, /etc/rc.d/growfs should haven grown its file system automatically. Otherwise run:
```console
# /etc/rc.d/growfs onestart
```
Verify that `uname -i` prints `SYZKALLER` to confirm that your newly built kernel is running.

Then, to permit remote access to the VM, you must configure DHCP and enable `sshd`:

```console
# sysrc sshd_enable=YES
# sysrc ifconfig_DEFAULT=DHCP
```

If you plan to run the syscall executor as root, ensure that root SSH logins are permitted by adding `PermitRootLogin without-password` to `/etc/ssh/sshd_config`.  Otherwise, create a new user with `adduser`.  Install an ssh key for the user and verify that you can SSH into the VM from the host.  Note that bhyve requires the use of the root user for the time being.

### Running Under bhyve

Some additional steps are required on the host in order to use bhyve.  First, since bhyve currently does not support disk image snapshots, ZFS must be used to provide equivalent functionality.  Create a ZFS data set and copy the VM image there.  The data set can also be used to store the syzkaller workdir.  For example, with a zpool named `data` mounted at `/data`, write:
```console
# zfs create data/syzkaller
# cp FreeBSD-13.3-CURRENT-amd64.raw /data/syzkaller
```
Third, configure bridged networking and DHCP for the VM instances.  This is no longer required on FreeBSD 14.1 and 15.0-CURRENT, as bhyve now supports libslirp-based user networking similar to the QEMU backend.

```console
# ifconfig bridge create
bridge0
# ifconfig bridge0 inet 169.254.0.1
# echo 'dhcp-range=169.254.0.2,169.254.0.254,255.255.255.0' > /usr/local/etc/dnsmasq.conf
# echo 'interface=bridge0' >> /usr/local/etc/dnsmasq.conf
# sysrc dnsmasq_enable=YES
# service dnsmasq start
# echo 'net.link.tap.up_on_open=1' >> /etc/sysctl.conf
# sysctl net.link.tap.up_on_open=1
```
To enable automatic configuration of bridged network every time the system boots, add the following to /etc/rc.conf:
```console
# cloned_interfaces="bridge0 tap0"
# ifconfig_bridge0="inet 169.254.0.1 addm tap0 up"
# ifconfig_tap0="up"
```
Finally, ensure that the bhyve kernel module is loaded:
```console
# kldload vmm
```

### Putting It All Together

If all of the above worked, create a `freebsd.cfg` configuration file with the following contents (alter paths as necessary):

```
{
	"name": "freebsd",
	"target": "freebsd/amd64",
	"http": ":10000",
	"workdir": "/workdir",
	"syzkaller": "/gopath/src/github.com/google/syzkaller",
	"sshkey": "/freebsd_id_rsa",
	"sandbox": "none",
	"procs": 8,
}
```
If running the fuzzer under QEMU, add:

```
	"image": "/FreeBSD-13.0-CURRENT-amd64.qcow2",
	"type": "qemu",
	"vm": {
		"count": 10,
		"cpu": 4,
		"mem": 2048
	}
```
For GCE, add the following instead (alter the storage bucket path as necessary):

```
	"image": "/FreeBSD-13.0-CURRENT-amd64.raw",
	"type": "gce",
	"vm": {
		"count": 10,
		"instance_type": "n1-standard-4",
		"gcs_path": "syzkaller"
	}
```
For bhyve, we need to specify the VM image snapshot name and networking info (alter the dataset name and paths as necessary):
```
	"image": "/data/syzkaller/FreeBSD-13.0-CURRENT-amd64.raw",
	"type": "bhyve",
	"vm": {
		"count": 10,
		"hostip": "169.254.0.1",
		"dataset": "data/syzkaller"
	}
```
If using bridged networking, the name of the bridge interface needs to be included in the "vm" block:
```
	"vm": {
		"count": 10,
		"hostip": "169.254.0.1",
		"dataset": "data/syzkaller",
        "bridge": "bridge0"
	}
```

Then, start `syz-manager` with:
```console
$ bin/syz-manager -config freebsd.cfg
```
It should start printing output along the lines of:
```
booting test machines...
wait for the connection from test machine...
machine check: 253 calls enabled, kcov=true, kleakcheck=false, faultinjection=false, comps=false
executed 3622, cover 1219, crashes 0, repro 0
executed 7921, cover 1239, crashes 0, repro 0
executed 32807, cover 1244, crashes 0, repro 0
executed 35803, cover 1248, crashes 0, repro 0
```
If something does not work, try adding the `-debug` flag to `syz-manager`.

## Missing things

- System call descriptions.  The initial list of FreeBSD system calls was a copy-and-paste of Linux's, and while they have been cleaned up over time they should be audited more carefully.  We are also still missing many system call descriptions.
- We should support fuzzing the Linux compatibility subsystem.
- We should provide instructions for fuzzing a FreeBSD system on ZFS
- `pkg/host` needs to be taught how to detect supported syscalls/devices.
- KCSAN for FreeBSD would be useful.
- On Linux we have emission of external networking/USB traffic into kernel using tun/gadgetfs. Implementing these for FreeBSD could uncover a number of high-profile bugs.
