# Setup: Linux host, QEMU vm, loongarch64 kernel

This document describes a Linux/QEMU setup for fuzzing a LoongArch64 Linux
kernel with syzkaller.

## Toolchain

You need:

- a Go toolchain supported by syzkaller,
- `loongarch64-linux-gnu-gcc`/`loongarch64-linux-gnu-g++`,
- `qemu-system-loongarch64`,
- Buildroot or another way to build an SSH-capable root filesystem.

The syzkaller target architecture is `loong64`, while the external Linux and
toolchain names remain `loongarch*`.
Use `TARGETARCH=loong64` and `TARGETVMARCH=loong64` when building syzkaller
target binaries.

## Kernel

Build a LoongArch kernel with KCOV and debugfs enabled. The following example
uses a GNU cross toolchain:

```shell
make ARCH=loongarch CROSS_COMPILE=loongarch64-linux-gnu- loongson64_defconfig

scripts/config \
	--enable KCOV \
	--enable KCOV_ENABLE_COMPARISONS \
	--enable KCOV_INSTRUMENT_ALL \
	--enable DEBUG_FS \
	--enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
	--enable VIRTIO_NET \
	--disable RANDOMIZE_BASE

make ARCH=loongarch CROSS_COMPILE=loongarch64-linux-gnu- olddefconfig
make ARCH=loongarch CROSS_COMPILE=loongarch64-linux-gnu- -j$(nproc)
```

The `loongson64_defconfig` uses 16 KiB pages. Confirm that the final config
contains:

```shell
grep '^CONFIG_PAGE_SIZE_16KB=y' .config
```

See the [recommended Linux kernel config options](kernel_configs.md) for more
coverage and bug-detection settings.

The QEMU setup below uses the EFI kernel image:

```
arch/loongarch/boot/vmlinux.efi
```

## Image

Buildroot provides a LoongArch virt defconfig:

```shell
make O=/buildroot-output qemu_loongarch64_virt_efi_defconfig
make O=/buildroot-output menuconfig
```

Choose the following options:

```
Target packages
	Networking applications
		[*] iproute2
		[*] openssh
Filesystem images
	[*] ext2/3/4 root filesystem
		ext2/3/4 variant - ext4
		exact size - 1g
```

Unselect:

```
Kernel
	Linux Kernel
```

Build the image once to populate `/buildroot-output/target`:

```shell
make O=/buildroot-output -j$(nproc)
```

Create an SSH key without a passphrase:

```shell
ssh-keygen -t rsa -N '' -f /image/id_rsa
chmod 0600 /image/id_rsa
```

Add the following lines to `/buildroot-output/target/etc/fstab`:

```
debugfs /sys/kernel/debug debugfs defaults 0 0
securityfs /sys/kernel/security securityfs defaults 0 0
```

Install the public key in the target filesystem:

```shell
install -Dm0600 /image/id_rsa.pub \
	/buildroot-output/target/root/.ssh/authorized_keys
```

Then replace `/buildroot-output/target/etc/ssh/sshd_config` with:

```
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
```

Run Buildroot again so these changes are included in the filesystem image:

```shell
make O=/buildroot-output -j$(nproc)
```

Use `/buildroot-output/images/rootfs.ext2` as the syzkaller `image` file.

## Test kernel and image

Run the kernel manually before starting syzkaller:

```shell
qemu-system-loongarch64 \
	-machine virt \
	-nographic \
	-m 2048 \
	-smp 2 \
	-kernel /linux/arch/loongarch/boot/vmlinux.efi \
	-append "root=/dev/vda console=ttyS0 rw nokaslr" \
	-object rng-random,filename=/dev/urandom,id=rng0 \
	-device virtio-rng-pci,rng=rng0 \
	-drive file=/buildroot-output/images/rootfs.ext2,if=none,format=raw,id=hd0 \
	-device virtio-blk-pci,drive=hd0 \
	-netdev user,id=net0,hostfwd=tcp::10022-:22 \
	-device virtio-net-pci,netdev=net0
```

Wait for the login prompt, then test SSH from another terminal:

```shell
ssh -i /image/id_rsa -p 10022 root@localhost
```

Inside the guest, confirm that KCOV is available:

```shell
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
mount -t securityfs none /sys/kernel/security 2>/dev/null || true
ls -l /sys/kernel/debug/kcov
```

## syzkaller

Build syzkaller as described in the generic [Linux setup guide](setup.md#go-and-syzkaller):

```shell
make TARGETOS=linux TARGETARCH=loong64 TARGETVMARCH=loong64 target
make manager
```

Create a manager config similar to the following one:

```json
{
	"name": "loong64",
	"target": "linux/loong64",
	"http": ":56700",
	"workdir": "/workdir",
	"kernel_obj": "/linux",
	"syzkaller": "/syzkaller",
	"image": "/buildroot-output/images/rootfs.ext2",
	"sshkey": "/image/id_rsa",
	"procs": 8,
	"type": "qemu",
	"vm": {
		"count": 1,
		"qemu": "qemu-system-loongarch64",
		"kernel": "/linux/arch/loongarch/boot/vmlinux.efi",
		"cmdline": "nokaslr",
		"cpu": 2,
		"mem": 2048
	}
}
```

Finally, run:

```shell
bin/syz-manager -config loong64.cfg
```

If startup fails, re-run with `-debug` and check the QEMU command line.
