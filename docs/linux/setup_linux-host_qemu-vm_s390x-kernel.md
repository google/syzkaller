# Setup: Debian/Ubuntu/Fedora host, QEMU vm, s390x kernel

## GCC

Obtain `s390x-linux-gnu-gcc` at least GCC version 9. The latest Debian/Ubuntu/Fedora distributions
should provide a recent enough version of a cross-compiler in the `gcc-s390x-linux-gnu` package.

## Kernel

Checkout Linux kernel source:

``` bash
git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git $KERNEL
```

Generate default configs:

``` bash
cd $KERNEL
make ARCH=s390 CROSS_COMPILE=s390x-linux-gnu- defconfig
make ARCH=s390 CROSS_COMPILE=s390x-linux-gnu- kvm_guest.config
```

Enable kernel config options required for syzkaller as described [here](kernel_configs.md).

```
./scripts/config --file .config \
                 -d MODULES \
                 -e KCOV \
                 -e KCOV_INSTRUMENT_ALL \
                 -e KCOV_ENABLE_COMPARISONS \
                 -e KASAN \
                 -e KASAN_INLINE \
                 -e CONFIGFS_FS \
                 -e SECURITYFS \
                 -e DEBUG_INFO \
                 -e GDB_SCRIPTS \
                 -e PRINTK \
                 -e EARLY_PRINTK \
                 -e DEVTMPFS \
                 -e TUN \
                 -e VIRTIO_PCI \
                 -e VIRTIO_NET \
                 -e NET_9P_VIRTIO \
                 -e NET_9P \
                 -e 9P_FS \
                 -e BINFMT_MISC \
                 -e FAULT_INJECTION \
                 -e FAILSLAB \
                 -e FAIL_PAGE_ALLOC \
                 -e FAIL_MAKE_REQUEST \
                 -e FAIL_IO_TIMEOUT \
                 -e FAIL_FUTEX \
                 -e FAULT_INJECTION_DEBUG_FS \
                 -e FAULT_INJECTION_STACKTRACE_FILTER \
                 -e DEBUG_KMEMLEAK
```

Edit `.config` file manually and enable them (or do that through `make menuconfig` if you prefer).

Since enabling these options results in more sub options being available, we need to regenerate config:

``` bash
make ARCH=s390 CROSS_COMPILE=s390x-linux-gnu- olddefconfig
```

Build the kernel:

```
make ARCH=s390 CROSS_COMPILE=s390x-linux-gnu- -j$(nproc)
```

Now you should have `vmlinux` (kernel binary) and `bzImage` (packed kernel image):

``` bash
$ ls $KERNEL/vmlinux
$KERNEL/vmlinux
$ ls $KERNEL/arch/s390/boot/bzImage
$KERNEL/arch/s390/boot/bzImage
```

## Image

### Debian

To create a Debian Linux image with the minimal set of required packages do:

```
cd $IMAGE/
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh
./create-image.sh -a s390x
```

The result should be `$IMAGE/bullseye.img` disk image.

For additional options of `create-image.sh`, please refer to `./create-image.sh -h`

## QEMU

### Debian

Run:

```shell
qemu-system-s390x \
	-M s390-ccw-virtio -cpu max,zpci=on -m 4G -smp 2 \
	-kernel $KERNEL/arch/s390/boot/bzImage \
	-drive file=$IMAGE/buster.img,if=virtio,format=raw \
	-append "rootwait root=/dev/vda net.ifnames=0 biosdevname=0" \
	-net nic,model=virtio -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-display none -serial mon:stdio \
	-pidfile vm.pid 2>&1 | tee vm.log
```

After that you should be able to ssh to QEMU instance in another terminal:

``` bash
ssh -i $IMAGE/buster.id_rsa -p 10021 -o "StrictHostKeyChecking no" root@localhost
```

If this fails with "too many tries", ssh may be passing default keys before
the one explicitly passed with `-i`. Append option `-o "IdentitiesOnly yes"`.

To kill the running QEMU instance press `Ctrl+A` and then `X` or run:

``` bash
kill $(cat vm.pid)
```

If QEMU works, the kernel boots and ssh succeeds, you can shutdown QEMU and try to run syzkaller.

## syzkaller

Build syzkaller as described [here](/docs/linux/setup.md#go-and-syzkaller), with `s390x` target:

```
make TARGETOS=linux TARGETARCH=s390x
```

Then create a manager config like the following, replacing the environment
variables `$GOPATH`, `$KERNEL` and `$IMAGE` with their actual values.

```
{
	"target": "linux/s390x",
	"http": "127.0.0.1:56741",
	"workdir": "$GOPATH/src/github.com/google/syzkaller/workdir",
	"kernel_obj": "$KERNEL",
	"image": "$IMAGE/buster.img",
	"sshkey": "$IMAGE/buster.id_rsa",
	"syzkaller": "$GOPATH/src/github.com/google/syzkaller",
	"procs": 8,
	"type": "qemu",
	"vm": {
		"count": 4,
		"kernel": "$KERNEL/arch/s390/boot/bzImage",
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
