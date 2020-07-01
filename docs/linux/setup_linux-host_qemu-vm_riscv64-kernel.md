# Setup: Debian/Ubuntu host, QEMU vm, riscv64 kernel

# GCC

Obtain `riscv64-linux-gnu-gcc` at least GCC version 8. The latest Debian/Ubuntu distributions should
provide both cross-compilers in a recent enough version in the `gcc-riscv64-linux-gnu` package.
Alternatively, you can also build your own
[RISC-V GNU compiler toolchain](https://github.com/riscv/riscv-gnu-toolchain) from source.

# Kernel

The following instructions were tested with Linux Kernel `v5.8-rc2`. In addition you need the
["riscv: Allow building with kcov coverage"](https://lore.kernel.org/linux-riscv/20200626124056.29708-1-tklauser@distanz.ch/)
patch. Create a kernel config with:

```shell
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- defconfig
```

Also enable the [recommended Kconfig options for syzkaller](/docs/linux/kernel_configs.md).

Then build kernel with:

```
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j $(nproc)
```

# OpenSBI

Clone the OpenSBI repository and build the bootable OpenSBI image containg the kernel:

```shell
git clone https://github.com/riscv/opensbi
cd opensbi
make CROSS_COMPILE=riscv64-linux-gnu- PLATFORM_RISCV_XLEN=64 PLATFORM=generic FW_PAYLOAD_PATH=<linux_build_directory>/arch/riscv/boot/Image
```

See the OpenSBI documentation for booting on the
[QEMU RISC-V Virt Machine Platform](https://github.com/riscv/opensbi/blob/master/docs/platform/qemu_virt.md)
for more information.

# Image

We will use buildroot to create the disk image. You can obtain buildroot
[here](https://buildroot.uclibc.org/download.html). The following instructions
were tested with buildroot version 2020.05. First run:

```shell
make qemu_riscv64_virt_defconfig
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
                ext2/3/4 variant - ext4
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

```shell
qemu-system-riscv64 \
	-machine virt \
	-nographic \
	-kernel /opensbi/build/platform/generic/firmware/fw_payload.elf \
	-append "root=/dev/vda ro console=ttyS0" \
	-object rng-random,filename=/dev/urandom,id=rng0 \
	-device virtio-rng-device,rng=rng0 \
	-drive file=/buildroot/output/images/rootfs.ext2,if=none,format=raw,id=hd0 \
	-device virtio-blk-device,drive=hd0 \
	-netdev user,id=net0,host=10.0.2.10,hostfwd=tcp::10022-:22 \
	-device virtio-net-device,netdev=net0
```

This should boot the kernel. Wait for login prompt, then in another console run:

```
ssh -p 10022 root@localhost
```

ssh should succeed.

# syzkaller

Build syzkaller as described [here](/docs/linux/setup.md#go-and-syzkaller), with `riscv64` target:

```
make TARGETOS=linux TARGETARCH=riscv64
```

Create the manager config `riscv64.cfg` similar to the following one (adjusting paths as necessary):

```
{
	"name": "riscv64",
	"target": "linux/riscv64",
	"http": ":56700",
	"workdir": "/workdir",
	"kernel_obj": "/linux",
	"syzkaller": "/gopath/src/github.com/google/syzkaller",
	"image": "/buildroot/output/images/rootfs.ext2",
	"procs": 8,
	"type": "qemu",
	"vm": {
		"count": 1,
		"kernel": "/opensbi/build/platform/generic/firmware/fw_payload.elf",
		"cpu": 2,
		"mem": 2048
	}
}
```

Finally, run `bin/syz-manager -config riscv64.cfg`. After it successfully starts, you should be able
to visit `localhost:56700` to view the fuzzing results.

In case you encounter issues with starting `syz-manager`, use the `-debug` flag and refer to the
[troubleshooting guide](/docs/troubleshooting.md).
