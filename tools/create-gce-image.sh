#!/bin/bash
# Copyright 2016 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# create-gce-image.sh creates a minimal bootable image suitable for syzkaller/GCE.
# The image will have password-less root login with a key stored in key file.
#
# Prerequisites:
# - you need a user-space system, a basic Debian system can be created with:
#   sudo debootstrap --include=openssh-server,curl,tar,time,strace stable debian
# - you need qemu-nbd, grub and maybe something else:
#   sudo apt-get install qemu-utils grub-efi
# - you need nbd support in kernel
# - you need kernel to use with image (e.g. arch/x86/boot/bzImage)
#   note: kernel modules are not supported
#
# Usage:
#   ./create-gce-image.sh /dir/with/user/space/system /path/to/bzImage
#
# If SYZ_SYSCTL_FILE env var is set and points to a file,
# then its contents will be appended to the image /etc/sysctl.conf.
# If SYZ_CMDLINE_FILE env var is set and points to a file,
# then its contents will be appended to the kernel command line.
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

# If the script is aborted at an unfortunate point, it leaves the whole system broken.
# E.g. we've seen that fdisk cannot update partition table until the next reboot.
# If you really need to kill it, use a different signal. But better wait.
trap "" SIGINT

if [ ! -e $1/sbin/init ]; then
	echo "usage: create-gce-image.sh /dir/with/user/space/system /path/to/bzImage"
	exit 1
fi

if [ "$(basename $2)" != "bzImage" ]; then
	echo "usage: create-gce-image.sh /dir/with/user/space/system /path/to/bzImage"
	exit 1
fi

# Clean up after previous unsuccessful run.
sudo umount disk.mnt || true
sudo qemu-nbd -d /dev/nbd0 || true
rm -rf disk.mnt disk.raw tag obj || true

sudo modprobe nbd
fallocate -l 2G disk.raw
sudo qemu-nbd -c /dev/nbd0 --format=raw disk.raw
mkdir -p disk.mnt
echo -en "o\nn\np\n1\n2048\n\na\n1\nw\n" | sudo fdisk /dev/nbd0
until [ -e /dev/nbd0p1 ]; do sleep 1; done
sudo mkfs.ext4 /dev/nbd0p1
sudo mount /dev/nbd0p1 disk.mnt
sudo cp -a $1/. disk.mnt/.
sudo cp $2 disk.mnt/vmlinuz
sudo sed -i "/^root/ { s/:x:/::/ }" disk.mnt/etc/passwd
echo "T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100" | sudo tee -a disk.mnt/etc/inittab
echo -en "auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet dhcp\n" | sudo tee disk.mnt/etc/network/interfaces
echo "debugfs /sys/kernel/debug debugfs defaults 0 0" | sudo tee -a disk.mnt/etc/fstab

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
	linux /vmlinuz root=/dev/sda1 console=ttyS0 earlyprintk=serial vsyscall=native rodata=n ftrace_dump_on_oops=orig_cpu oops=panic panic_on_warn=1 nmi_watchdog=panic panic=86400 $CMDLINE
}
EOF
sudo grub-install --target=i386-pc --boot-directory=disk.mnt/boot --no-floppy /dev/nbd0
sudo umount disk.mnt
rm -rf disk.mnt
sudo qemu-nbd -d /dev/nbd0
