# Setup: Ubuntu host, QEMU vm, x86-64 kernel

These are the instructions on how to fuzz the x86-64 kernel in a QEMU with Ubuntu on the host machine and Debian Stretch in the QEMU instances.

In the instructions below, the `$VAR` notation (e.g. `$GCC`, `$KERNEL`, etc.) is used to denote paths to directories that are either created when executing the instructions (e.g. when unpacking GCC archive, a directory will be created), or that you have to create yourself before running the instructions. Substitute the values for those variables manually.


## Install Prerequisites

Command:
``` bash
sudo apt update
sudo apt install make gcc flex bison libncurses-dev libelf-dev libssl-dev
```


## GCC

If your distro's GCC is older, it's preferable to get the latest GCC from [this](/docs/syzbot.md#crash-does-not-reproduce) list. Download and unpack into `$GCC`, and you should have GCC binaries in `$GCC/bin/`

>**Ubuntu 20.04 LTS**: You can ignore this section. GCC is up-to-date.

Command:
``` bash
ls $GCC/bin/
# Sample output:
# cpp     gcc-ranlib  x86_64-pc-linux-gnu-gcc        x86_64-pc-linux-gnu-gcc-ranlib
# gcc     gcov        x86_64-pc-linux-gnu-gcc-9.0.0
# gcc-ar  gcov-dump   x86_64-pc-linux-gnu-gcc-ar
# gcc-nm  gcov-tool   x86_64-pc-linux-gnu-gcc-nm
```

## Kernel

### Checkout Linux Kernel source

Command:
``` bash
git clone --branch v5.14 git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git $KERNEL
```

>We recommend to start with the latest stable version. v5.14 is an example here.

### Generate default configs

Command:
``` bash
cd $KERNEL
make defconfig
make kvm_guest.config
```

Or if you want to specify a compiler.

Command:
``` bash
cd $KERNEL
make CC="$GCC/bin/gcc" defconfig
make CC="$GCC/bin/gcc" kvm_guest.config
```

### Enable required config options

Enable kernel config options required for syzkaller as described [here](kernel_configs.md).
It's not required to enable all of them, but at the very least you need:

``` make
# Coverage collection.
CONFIG_KCOV=y

# Debug info for symbolization.
CONFIG_DEBUG_INFO=y

# Memory bug detector
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y

# Required for Debian Stretch
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
```

Edit `.config` file manually and enable them (or do that through `make menuconfig` if you prefer).

Since enabling these options results in more sub options being available, we need to regenerate config:

Command:
``` bash
make olddefconfig
```

Or if you want to specify a compiler.

Command:
``` bash
make CC="$GCC/bin/gcc" olddefconfig
```

You might also be interested in disabling the Predictable Network Interface Names mechanism. This can be disabled either in the syzkaller configuration (see details [here](troubleshooting.md)) or by updating these kernel configuration parameters:

``` make
CONFIG_CMDLINE_BOOL=y
CONFIG_CMDLINE="net.ifnames=0"
```

### Build the Kernel

Command:
``` bash
make -j`nproc`
```

Or if you want to specify a compiler.

Command:
``` bash
make CC="$GCC/bin/gcc" -j`nproc`
```

Now you should have `vmlinux` (kernel binary) and `bzImage` (packed kernel image):

Command:
``` bash
ls $KERNEL/vmlinux
# sample output - $KERNEL/vmlinux
ls $KERNEL/arch/x86/boot/bzImage
# sample output - $KERNEL/arch/x86/boot/bzImage
```

## Image

### Install debootstrap

Command:
``` bash
sudo apt install debootstrap
```

### Create Debian Stretch Linux image

Create a Debian Stretch Linux image with the minimal set of required packages.

Command:
``` bash
mkdir $IMAGE
cd $IMAGE/
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh
./create-image.sh
```

The result should be `$IMAGE/stretch.img` disk image.

### OR Create Debian Buster Linux image

Command:
``` bash
./create-image.sh --distribution buster
```

### Image extra tools

Sometimes it's useful to have some additional packages and tools available in the VM even though they are not required to run syzkaller. To install a set of tools we find useful do (feel free to edit the list of tools in the script):

Command:
``` bash
./create-image.sh --feature full
```

To install perf (not required to run syzkaller; requires `$KERNEL` to point to the kernel sources):

Command:
``` bash
./create-image.sh --add-perf
```

For additional options of `create-image.sh`, please refer to `./create-image.sh -h`

## QEMU

### Install QEMU

Command:
``` bash
sudo apt install qemu-system-x86
```

### Verify

Make sure the kernel boots and `sshd` starts.

Command:
``` bash
qemu-system-x86_64 \
	-m 2G \
	-smp 2 \
	-kernel $KERNEL/arch/x86/boot/bzImage \
	-append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
	-drive file=$IMAGE/stretch.img,format=raw \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-enable-kvm \
	-nographic \
	-pidfile vm.pid \
	2>&1 | tee vm.log
```

``` text
early console in setup code
early console in extract_kernel
input_data: 0x0000000005d9e276
input_len: 0x0000000001da5af3
output: 0x0000000001000000
output_len: 0x00000000058799f8
kernel_total_size: 0x0000000006b63000

Decompressing Linux... Parsing ELF... done.
Booting the kernel.
[    0.000000] Linux version 4.12.0-rc3+ ...
[    0.000000] Command line: console=ttyS0 root=/dev/sda debug earlyprintk=serial
...
[ ok ] Starting enhanced syslogd: rsyslogd.
[ ok ] Starting periodic command scheduler: cron.
[ ok ] Starting OpenBSD Secure Shell server: sshd.
```

After that you should be able to ssh to QEMU instance in another terminal.

Command:
``` bash
ssh -i $IMAGE/stretch.id_rsa -p 10021 -o "StrictHostKeyChecking no" root@localhost
```

### Troubleshooting

If this fails with "too many tries", ssh may be passing default keys before
the one explicitly passed with `-i`. Append option `-o "IdentitiesOnly yes"`.

To kill the running QEMU instance press `Ctrl+A` and then `X` or run:

Command:
``` bash
kill $(cat vm.pid)
```

If QEMU works, the kernel boots and ssh succeeds, you can shutdown QEMU and try to run syzkaller.

## syzkaller

Build syzkaller as described [here](/docs/linux/setup.md#go-and-syzkaller).
Then create a manager config like the following, replacing the environment
variables `$GOPATH`, `$KERNEL` and `$IMAGE` with their actual values.

``` json
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
		"cpu": 2,
		"mem": 2048
	}
}
```

Run syzkaller manager:

``` bash
mkdir workdir
./bin/syz-manager -config=my.cfg
```

Now syzkaller should be running, you can check manager status with your web browser at `127.0.0.1:56741`.

If you get issues after `syz-manager` starts, consider running it with the `-debug` flag.
Also see [this page](/docs/troubleshooting.md) for troubleshooting tips.
