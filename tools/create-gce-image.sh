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
#   ./create-gce-image.sh /dir/with/user/space/system /path/to/bzImage /path/to/vmlinux 'image tag'
#
# The image can then be uploaded to GCS with:
#   gsutil cp disk.tar.gz gs://my-images
# and then my-images/disk.tar.gz can be used to create new GCE bootable image.
# image.tar.gz can be used with syz-gce.
#
# The image can be tested locally with e.g.:
#   qemu-system-x86_64 -hda disk.raw -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 -net nic -enable-kvm -m 2G -display none -serial stdio
# once the kernel boots, you can ssh into it with:
#   ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -p 10022 -i key root@localhost
#
# Note: the script creates and deletes some failes in cwd.

set -eux

if [ ! -e $1/sbin/init ]; then
	echo "usage: create-gce-image.sh /dir/with/user/space/system /path/to/bzImage /path/to/vmlinux 'image tag'"
	exit 1
fi

if [ "$(basename $2)" != "bzImage" ]; then
	echo "usage: create-gce-image.sh /dir/with/user/space/system /path/to/bzImage /path/to/vmlinux 'image tag'"
	exit 1
fi

if [ "$(basename $3)" != "vmlinux" ]; then
	echo "usage: create-gce-image.sh /dir/with/user/space/system /path/to/bzImage /path/to/vmlinux 'image tag'"
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
echo -en "\nauto eth0\niface eth0 inet dhcp\n" | sudo tee -a disk.mnt/etc/network/interfaces
echo "debugfs /sys/kernel/debug debugfs defaults 0 0" | sudo tee -a disk.mnt/etc/fstab
echo "kernel.printk = 7 4 1 3" | sudo tee -a disk.mnt/etc/sysctl.conf
echo "debug.exception-trace = 0" | sudo tee -a disk.mnt/etc/sysctl.conf
echo "net.core.bpf_jit_enable = 1" | sudo tee -a disk.mnt/etc/sysctl.conf
echo "net.core.bpf_jit_harden = 2" | sudo tee -a disk.mnt/etc/sysctl.conf
echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a disk.mnt/etc/sysctl.conf
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
cat << EOF | sudo tee disk.mnt/boot/grub/grub.cfg
terminal_input console
terminal_output console
set timeout=0
# vsyscall=native: required to run x86_64 executables on android kernels (for some reason they disable VDSO by default)
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
	linux /vmlinuz root=/dev/sda1 console=ttyS0 earlyprintk=serial vsyscall=native rodata=n ftrace_dump_on_oops=orig_cpu oops=panic panic_on_warn=1 panic=86400 kvm-intel.nested=1 kvm-intel.unrestricted_guest=1 kvm-intel.vmm_exclusive=1 kvm-intel.fasteoi=1 kvm-intel.ept=1 kvm-intel.flexpriority=1 kvm-intel.vpid=1 kvm-intel.emulate_invalid_guest_state=1 kvm-intel.eptad=1 kvm-intel.enable_shadow_vmcs=1 kvm-intel.pml=1 kvm-intel.enable_apicv=1
}
EOF
sudo grub-install --boot-directory=disk.mnt/boot --no-floppy /dev/nbd0
sudo umount disk.mnt
rm -rf disk.mnt
sudo qemu-nbd -d /dev/nbd0
tar -Szcf disk.tar.gz disk.raw
mkdir -p obj
cp $3 obj/
echo -n "$4" > tag
tar -czvf image.tar.gz disk.tar.gz key tag obj/vmlinux
rm -rf tag obj
