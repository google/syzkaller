#!/bin/bash
# Copyright 2016 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# create-gce-image.sh creates a minimal bootable image suitable for syzkaller/GCE.
# The image will have password-less root login with a key stored in key file.
#
# Prerequisites:
# - you need a user-space system, a basic Debian system can be created with:
#   sudo debootstrap --include=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default,firmware-atheros --components=main,contrib,non-free stable debian
# - you need kernel to use with image (e.g. arch/x86/boot/bzImage)
#   note: kernel modules are not supported
# - you need grub:
#   sudo apt-get install grub-efi
#
# Usage:
#   ./create-gce-image.sh /dir/with/user/space/system /path/to/{zImage,bzImage} [arch]
#
# SYZ_VM_TYPE env var controls type of target test machine. Supported values:
# - qemu (default)
# - gce
#   Needs nbd support in kernel and qemu-utils (qemu-nbd) installed.
#
# If SYZ_SYSCTL_FILE env var is set and points to a file,
# then its contents will be appended to the image /etc/sysctl.conf.
# If SYZ_CMDLINE_FILE env var is set and points to a file,
# then its contents will be appended to the kernel command line.
# If MKE2FS_CONFIG env var is set, it will affect invoked mkfs.ext4.
#
# Outputs are (in the current dir):
# - disk.raw: the image
# - key: root ssh key
# The script can also create/delete temp files in the current dir.
#
# The image then needs to be compressed with:
#   tar -Sczf disk.tar.gz disk.raw
# and uploaded to GCS with:
#   gsutil cp disk.tar.gz gs://my-images/image.tar.gz
# finally, my-images/image.tar.gz can be used to create a new GCE image.
#
# The image can be tested locally with e.g.:
#   qemu-system-x86_64 -hda disk.raw -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 \
#       -net nic -enable-kvm -m 2G -display none -serial stdio
# once the kernel boots, you can ssh into it with:
#   ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes \
#       -p 10022 -i key root@localhost

set -eux

CLEANUP=""
trap 'eval " $CLEANUP"' EXIT

IMG_ARCH="${3:-amd64}"

if [ ! -e $1/sbin/init ]; then
	echo "usage: create-gce-image.sh /dir/with/user/space/system /path/to/bzImage [arch]"
	exit 1
fi

case "$IMG_ARCH" in
	386|amd64)
		KERNEL_IMAGE_BASENAME=bzImage
		;;
	ppc64le)
		KERNEL_IMAGE_BASENAME=zImage.pseries
		;;
esac

if [ "$(basename $2)" != "$KERNEL_IMAGE_BASENAME" ]; then
	echo "usage: create-gce-image.sh /dir/with/user/space/system /path/to/bzImage [arch]"
	exit 1
fi

SYZ_VM_TYPE="${SYZ_VM_TYPE:-qemu}"
if [ "$SYZ_VM_TYPE" == "qemu" ]; then
	:
elif [ "$SYZ_VM_TYPE" == "gce" ]; then
	:
else
	echo "SYZ_VM_TYPE has unsupported value $SYZ_VM_TYPE"
	exit 1
fi

# qemu-nbd is broken on Debian with:
#	Calling ioctl() to re-read partition table.
#	Re-reading the partition table failed.: Invalid argument
#	The kernel still uses the old table. The new table will be used at the
#	next reboot or after you run partprobe(8) or kpartx(8).
# losetup is broken on Ubuntu with some other error.
# Try to figure out what will work.
BLOCK_DEVICE="loop"
if [ "$(uname -a | grep Ubuntu)" != "" ]; then
	BLOCK_DEVICE="nbd"
fi

# Clean up after previous unsuccessful run.
sudo umount disk.mnt || true
if [ "$BLOCK_DEVICE" == "loop" ]; then
	:
elif [ "$BLOCK_DEVICE" == "nbd" ]; then
	sudo modprobe nbd
	sudo qemu-nbd -d /dev/nbd0 || true
fi
rm -rf disk.mnt disk.raw || true

fallocate -l 2G disk.raw
if [ "$BLOCK_DEVICE" == "loop" ]; then
	DISKDEV="$(sudo losetup -f --show -P disk.raw)"
	CLEANUP="sudo losetup -d $DISKDEV; $CLEANUP"
elif [ "$BLOCK_DEVICE" == "nbd" ]; then
	DISKDEV="/dev/nbd0"
	sudo qemu-nbd -c $DISKDEV --format=raw disk.raw
	CLEANUP="sudo qemu-nbd -d $DISKDEV; $CLEANUP"
fi

case "$IMG_ARCH" in
	386|amd64)
		echo -en "o\nn\np\n1\n\n\na\nw\n" | sudo fdisk $DISKDEV
		PARTDEV=$DISKDEV"p1"
		;;
	ppc64le)
		# Create a small PowerPC PReP boot partition, and a Linux partition for the rest
		echo -en "g\nn\n1\n2048\n16383\nt\n7\nn\n2\n\n\nw\n" | sudo fdisk $DISKDEV
		PARTDEV=$DISKDEV"p2"
		;;
esac

until [ -e $PARTDEV ]; do sleep 1; done
sudo -E mkfs.ext4 -O ^resize_inode,^has_journal,ext_attr,extents,huge_file,flex_bg,dir_nlink,sparse_super $PARTDEV
mkdir -p disk.mnt
CLEANUP="rm -rf disk.mnt; $CLEANUP"
sudo mount $PARTDEV disk.mnt
CLEANUP="sudo umount disk.mnt; $CLEANUP"
sudo cp -a $1/. disk.mnt/.
sudo cp $2 disk.mnt/vmlinuz
sudo sed -i "/^root/ { s/:x:/::/ }" disk.mnt/etc/passwd
echo "T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100" | sudo tee -a disk.mnt/etc/inittab
echo -en "auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet dhcp\n" | sudo tee disk.mnt/etc/network/interfaces
echo "debugfs /sys/kernel/debug debugfs defaults 0 0" | sudo tee -a disk.mnt/etc/fstab
echo "securityfs /sys/kernel/security securityfs defaults 0 0" | sudo tee -a disk.mnt/etc/fstab
echo "configfs /sys/kernel/config/ configfs defaults 0 0" | sudo tee -a disk.mnt/etc/fstab
echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a disk.mnt/etc/fstab
for i in {0..31}; do
	echo "KERNEL==\"binder$i\", NAME=\"binder$i\", MODE=\"0666\"" | \
		sudo tee -a disk.mnt/etc/udev/50-binder.rules
done

# Add udev rules for custom drivers.
# Create a /dev/vim2m symlink for the device managed by the vim2m driver
echo 'ATTR{name}=="vim2m", SYMLINK+="vim2m"' | sudo tee -a disk.mnt/etc/udev/rules.d/50-udev-default.rules

# Create a /dev/i915 symlink to /dev/dri/card# if i915 driver is in use.
echo 'SUBSYSTEMS=="pci", DRIVERS=="i915", SYMLINK+="i915"' | sudo tee -a disk.mnt/etc/udev/rules.d/60-drm.rules

# sysctls
echo "kernel.printk = 7 4 1 3" | sudo tee -a disk.mnt/etc/sysctl.conf
echo "debug.exception-trace = 0" | sudo tee -a disk.mnt/etc/sysctl.conf
SYZ_SYSCTL_FILE="${SYZ_SYSCTL_FILE:-}"
if [ "$SYZ_SYSCTL_FILE" != "" ]; then
	cat $SYZ_SYSCTL_FILE | sudo tee -a disk.mnt/etc/sysctl.conf
fi

echo -en "127.0.0.1\tlocalhost\n" | sudo tee disk.mnt/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a disk.mnt/etc/resolve.conf
echo "ClientAliveInterval 420" | sudo tee -a disk.mnt/etc/ssh/sshd_config
echo "syzkaller" | sudo tee disk.mnt/etc/hostname
rm -f key key.pub
ssh-keygen -f key -t rsa -N ""
sudo mkdir -p disk.mnt/root/.ssh
sudo cp key.pub disk.mnt/root/.ssh/authorized_keys
sudo chown root disk.mnt/root/.ssh/authorized_keys
sudo mkdir -p disk.mnt/boot/grub

CMDLINE=""
SYZ_CMDLINE_FILE="${SYZ_CMDLINE_FILE:-}"
if [ "$SYZ_CMDLINE_FILE" != "" ]; then
	CMDLINE=$(awk '{printf("%s ", $0)}' $SYZ_CMDLINE_FILE)
fi

case "$IMG_ARCH" in
386|amd64)
	cat << EOF | sudo tee disk.mnt/boot/grub/grub.cfg
terminal_input console
terminal_output console
set timeout=0
# vsyscall=native: required to run x86_64 executables on android kernels
#   (for some reason they disable VDSO by default)
# rodata=n: mark_rodata_ro becomes very slow with KASAN (lots of PGDs)
# panic=86400: prevents kernel from rebooting so that we don't get reboot output in all crash reports
# debug is not set as it produces too much output
menuentry 'linux' --class gnu-linux --class gnu --class os {
	insmod vbe
	insmod vga
	insmod video_bochs
	insmod video_cirrus
	insmod gzio
	insmod part_msdos
	insmod ext2
	set root='(hd0,1)'
	linux /vmlinuz root=/dev/sda1 console=ttyS0 earlyprintk=serial vsyscall=native rodata=n oops=panic panic_on_warn=1 nmi_watchdog=panic panic=86400 net.ifnames=0 sysctl.kernel.hung_task_all_cpu_backtrace=1 $CMDLINE
}
EOF
	sudo grub-install --target=i386-pc --boot-directory=disk.mnt/boot --no-floppy $DISKDEV
	;;
ppc64le)
	cat << EOF | sudo tee disk.mnt/boot/grub/grub.cfg
terminal_input console
terminal_output console
set timeout=0
# rodata=n: mark_rodata_ro becomes very slow with KASAN (lots of PGDs)
# panic=86400: prevents kernel from rebooting so that we don't get reboot output in all crash reports
# debug is not set as it produces too much output
menuentry 'linux' --class gnu-linux --class gnu --class os {
	insmod gzio
	insmod part_gpt
	insmod ext2
	set root='(ieee1275/disk,gpt2)'
	linux /vmlinuz root=/dev/sda2 console=ttyS0 earlyprintk=serial rodata=n oops=panic panic_on_warn=1 nmi_watchdog=panic panic=86400 net.ifnames=0 $CMDLINE
}
EOF
	sudo grub-install --target=powerpc-ieee1275 --boot-directory=disk.mnt/boot $DISKDEV"p1"
	;;
esac
