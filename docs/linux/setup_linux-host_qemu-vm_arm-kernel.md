# Setup: Debian host, QEMU vm, arm kernel

# GCC

Obtain a fresh `arm-linux-gnueabihf-gcc`. Latest Debian distributions provide
version 7.2.0, which should be enough. Otherwise you can download Linaro
compiler [here](https://www.linaro.org/downloads).
 
# Kernel

The instructions are tested with `v4.16.1`. Check that you have/backport
["arm: port KCOV to arm"](https://groups.google.com/d/msg/syzkaller/zLThPHplyIc/9ncfpRvVCAAJ)
patch. Create kernel config with:

```shell
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- vexpress_defconfig
```

Then enable the following configs on top:

```
CONFIG_KCOV=y
CONFIG_DEBUG_INFO=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_NAMESPACES=y
CONFIG_USER_NS=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
```

Also check out general kernel configuration [recommendations](/docs/linux/kernel_configs.md).

Then build kernel with:

```
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi-
```

# Image

We will use buildroot to create the disk image. You can obtain buildroot
[here](https://buildroot.uclibc.org/download.html). Instructions were tested
with buildroot `c665c7c9cd6646b135cdd9aa7036809f7771ab80`. First run:

```
make qemu_arm_vexpress_defconfig
make menuconfig
```

Choose the following options:

```
    Target packages
	    Networking applications
	        [*] dhcpcd
	        [*] iproute2
	        [*] openssh
    Filesystem images
	        exact size - 1g
```

Unselect:

```
    Kernel
	    Linux Kernel
```

Run `make`.

Then add the following line to `output/target/etc/fstab`:

```
debugfs	/sys/kernel/debug	debugfs	defaults	0	0
```

Then replace `output/target/etc/ssh/sshd_config` with the following contents:
 
```
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
```

Run `make` again.

# Test kernel and image

Run:

```
qemu-system-arm -m 512 -smp 2 -net nic -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 -display none -serial stdio -machine vexpress-a15 -dtb /linux/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb -sd /buildroot/output/images/rootfs.ext2 -snapshot -kernel /linux/arch/arm/boot/zImage -append "earlyprintk=serial console=ttyAMA0 root=/dev/mmcblk0"
```

This should boot the kernel. Wait for login prompt, then in another console run:

```
ssh -p 10022 root@localhost
```

ssh should succeed.

# syzkaller

Build syzkaller as described [here](/docs/linux/setup.md#go-and-syzkaller), with `arm` target:

```
make TARGETOS=linux TARGETARCH=arm
```

Create manager config `arm.cfg` similar to the following one (changing paths as necessary):

```
{
	"name": "arm",
	"target": "linux/arm",
	"http": ":12345",
	"workdir": "/workdir",
	"kernel_obj": "/linux",
	"syzkaller": "/gopath/src/github.com/google/syzkaller",
	"image": "/buildroot/output/images/rootfs.ext2",
	"sandbox": "none",
	"reproduce": false,
	"procs": 4,
	"type": "qemu",
	"vm": {
		"count": 10,
		"qemu_args": "-machine vexpress-a15 -dtb /linux/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb",
		"cmdline": "console=ttyAMA0 root=/dev/mmcblk0",
		"kernel": "/linux/arch/arm/boot/zImage",
		"image_device": "sd",
		"mem": 512,
		"cpu": 2
	}
}
```

Finally, run `bin/syz-manager -config arm.cfg`.
