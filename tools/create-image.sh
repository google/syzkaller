#!/bin/bash
# Copyright 2016 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# create-image.sh creates a minimal Debian-wheezy Linux image suitable for syzkaller.

set -eux

# Create a minimal Debian-wheezy distributive as a directory.
sudo rm -rf wheezy
mkdir -p wheezy
sudo debootstrap --include=openssh-server,curl,tar,time,strace,sudo,less,psmisc wheezy wheezy

# Set some defaults and enable promtless ssh to the machine for root.
sudo sed -i '/^root/ { s/:x:/::/ }' wheezy/etc/passwd
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a wheezy/etc/inittab
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a wheezy/etc/network/interfaces
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a wheezy/etc/fstab
echo "kernel.printk = 7 4 1 3" | sudo tee -a wheezy/etc/sysctl.conf
echo 'debug.exception-trace = 0' | sudo tee -a wheezy/etc/sysctl.conf
echo "net.core.bpf_jit_enable = 1" | sudo tee -a wheezy/etc/sysctl.conf
echo "net.core.bpf_jit_harden = 2" | sudo tee -a wheezy/etc/sysctl.conf
echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a wheezy/etc/sysctl.conf
sudo mkdir -p wheezy/root/.ssh/
rm -rf ssh
mkdir -p ssh
ssh-keygen -f ssh/id_rsa -t rsa -N ''
cat ssh/id_rsa.pub | sudo tee wheezy/root/.ssh/authorized_keys

# Build a disk image
dd if=/dev/zero of=wheezy.img bs=1M seek=1023 count=1
mkfs.ext4 -F wheezy.img
sudo mkdir -p /mnt/wheezy
sudo mount -o loop wheezy.img /mnt/wheezy
sudo cp -a wheezy/. /mnt/wheezy/.
sudo umount /mnt/wheezy
