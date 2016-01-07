#!/bin/bash
# Copyright 2016 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# create-image.sh creates a minimal Debian-wheezy Linux image suitable for syzkaller.

set -eux

# Create a minimal Debian-wheezy distributive as a directory.
sudo rm -rf wheezy
mkdir -p wheezy
sudo debootstrap --include=openssh-server wheezy wheezy

# Set some defaults and enable promtless ssh to the machine for root.
sudo sed -i '/^root/ { s/:x:/::/ }' wheezy/etc/passwd
echo 'V0:23:respawn:/sbin/getty 115200 hvc0' | sudo tee -a wheezy/etc/inittab
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a wheezy/etc/network/interfaces
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a wheezy/etc/fstab
echo 'debug.exception-trace = 0' | sudo tee -a wheezy/etc/sysctl.conf
sudo mkdir wheezy/root/.ssh/
rm -rf ssh
mkdir -p ssh
ssh-keygen -f ssh/id_rsa -t rsa -N ''
cat ssh/id_rsa.pub | sudo tee wheezy/root/.ssh/authorized_keys

# Install some misc packages.
sudo chroot wheezy /bin/bash -c "apt-get update; ( yes | apt-get install curl tar time strace)"

# Build a disk image
dd if=/dev/zero of=wheezy.img bs=1M seek=1023 count=1
mkfs.ext4 -F wheezy.img
sudo mkdir -p /mnt/wheezy
sudo mount -o loop wheezy.img /mnt/wheezy
sudo cp -a wheezy/. /mnt/wheezy/.
sudo umount /mnt/wheezy

