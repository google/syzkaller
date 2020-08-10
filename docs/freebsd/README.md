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
$ go get -u -d github.com/google/syzkaller/prog
```
and the binaries can be built by running:
```console
$ cd go/src/github.com/google/syzkaller/
$ gmake
```

Once this completes, a `syz-manager` executable should be available under `bin/`.

### Setting up a Linux host

To build Go binaries do:
```
make manager fuzzer execprog TARGETOS=freebsd
```
To build C `syz-executor` binary, copy `executor/*` files to a FreeBSD machine and build there with:
```
c++ executor/executor_freebsd.cc -o syz-executor -O1 -lpthread -DGOOS=\"freebsd\" -DGIT_REVISION=\"CURRENT_GIT_REVISION\"
```
Then, copy out the binary back to host into `bin/freebsd_amd64` dir.

## Setting up the FreeBSD VM

It is easiest to start with a [snapshot image](http://ftp.freebsd.org/pub/FreeBSD/snapshots/VM-IMAGES/13.0-CURRENT/amd64/Latest/) of FreeBSD.  Fetch a QCOW2 disk image for QEMU or a raw image for GCE or bhyve.

To enable KCOV on FreeBSD, a custom kernel must be compiled.  It is easiest to do this in the VM itself.  Use QEMU to start a VM using the downloaded image:

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
Fetch a copy of the FreeBSD kernel sources and place them in `/usr/src`.  For instance, to get a copy of the current development sources, run:

```console
# pkg install git
# git clone --depth=1 --branch=master https://github.com/freebsd/freebsd /usr/src
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
# make KERNCONF=SYZKALLER installkernel
# shutdown -r now
```
When the VM is restarted, verify that `uname -i` prints `SYZKALLER` to confirm that your newly built kernel is running.

Then, to permit remote access to the VM, you must configure DHCP and enable `sshd`:

```console
# sysrc sshd_enable=YES
# sysrc ifconfig_DEFAULT=DHCP
```

If you plan to run the syscall executor as root, ensure that root SSH logins are permitted by adding `PermitRootLogin without-password` to `/etc/ssh/sshd_config`.  Otherwise, create a new user with `adduser`.  Install an ssh key for the user and verify that you can SSH into the VM from the host.  Note that bhyve requires the use of the root user for the time being.

### Running Under bhyve

Some additional steps are required on the host in order to use bhyve.  First, ensure that the host system is at r346550 or later.  Second, since bhyve currently does not support disk image snapshots, ZFS must be used to provide equivalent functionality.  Create a ZFS data set and copy the VM image there.  The data set can also be used to store the syzkaller workdir.  For example, with a zpool named `data` mounted at `/data`, write:
```console
# zfs create data/syzkaller
# cp FreeBSD-13.0-CURRENT-amd64.raw /data/syzkaller
```
Third, configure networking and DHCP for the VM instances:

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
		"bridge": "bridge0",
		"hostip": "169.254.0.1",
		"dataset": "data/syzkaller"
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
- KASAN and KCSAN for FreeBSD would be useful.
- On Linux we have emission of exernal networking/USB traffic into kernel using tun/gadgetfs. Implementing these for FreeBSD could uncover a number of high-profile bugs.
