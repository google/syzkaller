# Setup: Linux host, crosvm vm, x86-64 kernel

These are the instructions on how to fuzz the x86-64 kernel in
[crosvm](https://crosvm.dev), the ChromeOS Virtual Machine Monitor.

crosvm differs from QEMU in ways that the `crosvm` VM type has to work around, and that you
need to know about when preparing the kernel and the image:

- **crosvm always boots the kernel directly.** There is no BIOS and no bootloader, so the
  `kernel` config parameter is mandatory and a kernel installed inside the image is not used.
  Everything the guest needs to reach its root filesystem (virtio-blk, the partition format
  and the root filesystem itself) must be built into the kernel, or supplied via `initrd`.
- **crosvm has no user mode networking on Linux.** Its slirp backend is Windows only, so
  the guest is reachable over a tap device rather than over a forwarded localhost port.
  There is no DHCP server either, so the guest address is configured by the kernel itself
  and the kernel needs `CONFIG_IP_PNP=y`.
- **crosvm cannot read compressed qcow2 images.** Most distributed cloud images are
  compressed and have to be converted first (see below).

## Kernel

Build the kernel as described in
[Setup: Ubuntu host, QEMU vm, x86-64 kernel](setup_ubuntu-host_qemu-vm_x86-64-kernel.md),
with the config options from [kernel_configs.md](kernel_configs.md), plus the options
crosvm needs:

``` make
# Guest networking is configured from the kernel command line.
CONFIG_IP_PNP=y

# Reaching the root filesystem without an initrd. Adjust the filesystem to your image.
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_PCI=y
CONFIG_EXT4_FS=y
CONFIG_EFI_PARTITION=y

# Only needed for snapshot fuzzing, see the section at the end.
CONFIG_DEVMEM=y
# CONFIG_IO_STRICT_DEVMEM is not set
```

These have to be built in rather than modular. Distribution kernels usually ship
`CONFIG_VIRTIO_BLK`, `CONFIG_EXT4_FS` and friends as modules, which is fine when an initrd
loads them, but crosvm boots the kernel directly. Either set them to `y`, or point the
`initrd` config parameter at an initramfs that contains them.

Watch out for what a built-in filesystem still pulls in at runtime. Building `vfat` in is
not enough on its own, because its codepage stays modular, and mounting an EFI system
partition then fails with `FAT-fs (vda15): codepage cp437 not found`, which is enough to
drop systemd into emergency mode where sshd never starts. Either add
`CONFIG_NLS_CODEPAGE_437=y` and `CONFIG_NLS_ISO8859_1=y`, or leave `/boot/efi` unmounted in
the image — a fuzzing guest has no use for it:

``` bash
systemctl mask boot-efi.mount
```

`kernel_obj` in the manager config must be the directory that holds `vmlinux`. That is the
source tree for an in-tree build, but not for a packaged or out-of-tree build: a kernel built
from Debian's own packaging, for instance, leaves `vmlinux` in
`debian/build/build_<arch>_none_<flavour>/` and the image in that directory's
`arch/x86/boot/bzImage`.

## Image

Create an image as described in the QEMU setup page. If you use a distribution cloud image,
convert it so that crosvm can read it — crosvm's qcow2 implementation rejects compressed
clusters with "compressed blocks not supported":

``` bash
qemu-img convert -O qcow2 image.qcow2 image-crosvm.qcow2
```

Raw images work as is. Every VM runs on its own copy-on-write overlay of the image
(`overlay` config parameter, on by default), so the image itself is never modified.

## crosvm

Build crosvm from its source tree:

``` bash
git submodule update --init third_party/minijail
cargo build --release --bin crosvm
```

crosvm's default feature set includes `gpu` and `slirp`; neither is needed here, and
dropping them cuts the dependency list considerably:

``` bash
cargo build --release --bin crosvm --no-default-features \
    --features qcow,balloon,net,usb,audio
```

### Networking

By default syzkaller lets crosvm create and configure a tap device per VM, giving the VM
with index `N` the network `192.168.<100+N>.0/24` with the host at `.1` and the guest at
`.2`. Creating a tap device requires `CAP_NET_ADMIN`:

``` bash
sudo setcap cap_net_admin+ep $(which crosvm)
```

Alternatively, pre-create persistent tap devices and point syzkaller at them with the
`tap_name` parameter, in which case `host_ip` and `guest_ip` must be set as well (both
accept `{{INDEX}}`):

``` bash
sudo ip tuntap add dev syz0 mode tap user $USER
sudo ip addr add 192.168.100.1/24 dev syz0
sudo ip link set syz0 up
```

## Configuration

``` json
{
	"target": "linux/amd64",
	"http": "127.0.0.1:56741",
	"workdir": "$WORKDIR",
	"kernel_obj": "$KERNEL",
	"image": "$IMAGE/image-crosvm.qcow2",
	"sshkey": "$IMAGE/image.id_rsa",
	"syzkaller": "$SYZKALLER",
	"procs": 8,
	"type": "crosvm",
	"vm": {
		"count": 4,
		"kernel": "$KERNEL/arch/x86/boot/bzImage",
		"cpu": 2,
		"mem": 2048,
		"root_device": "/dev/vda1"
	}
}
```

The `crosvm` parameter selects the binary (`crosvm` by default). `cmdline` appends to the
kernel command line, `crosvm_args` appends to the crosvm command line, and both `tap_name`
and `crosvm_args` expand `{{INDEX}}` to the 0-based VM index.

If the guest names its interface something other than `eth0` — that is, if the kernel was
built without `net.ifnames=0` in `CONFIG_CMDLINE` — set `network_device` to the interface
name, or to an empty string to configure all interfaces.

## Snapshot fuzzing

Snapshot mode (`"snapshot": true` in the manager config) is supported, but with an
important caveat compared to QEMU.

QEMU restores a snapshot in-process with `loadvm`, and the guest and host exchange inputs
and results through an ivshmem device whose doorbell interrupt wakes the other side.
crosvm has neither: its control socket only implements `snapshot take`, and restoring is a
startup-only operation (`crosvm run --restore`). So syzkaller restores a snapshot by
killing the VM and starting a new crosvm process from the snapshot directory, which is
considerably slower than QEMU's in-process restore, and both sides poll the shared memory
instead of being interrupted.

The shared memory itself is a file-backed MMIO mapping (`--file-backed-mapping`) at a fixed
guest physical address, which the executor maps through `/dev/mem`. Mapping it needs
`CONFIG_DEVMEM=y`; `CONFIG_STRICT_DEVMEM=y` is fine because the region is MMIO rather than
RAM, but `CONFIG_IO_STRICT_DEVMEM=y` is not — it is enabled in distribution kernels, so it
has to be turned off explicitly. Being MMIO is also what keeps the region out
of the snapshot — crosvm only serializes guest RAM — so a new input can be written before
each restore, the same way QEMU's `x-ignore-shared` works.
