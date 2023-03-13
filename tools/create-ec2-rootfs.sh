#!/usr/bin/env bash
# Copyright 2023 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
#
# Author: Kuniyuki Iwashima <kuniyu@amazon.com>
#
# create-ec2-rootfs.sh creates a rootfs from AL2023 container image.
#
# Usage:
#
#   1) Create a rootfs
#
#     ./create-ec2-rootfs.sh -f xfs -n rootfs.xfs -s 2G
#
#   2) Extend a rootfs
#
#     ./create-ec2-rootfs.sh -f xfs -n rootfs.xfs -s 4G
#
# The image can be tested locally with e.g.:
#
#   qemu-system-x86_64 -boot c -m 2G -kernel ${PATH_TO_bzImage} -hda ${PATH_TO_ROOTFS} \
#                      -append "root=/dev/sda rw console=ttyS0,115200" \
#                      -serial stdio -display none -nic user,hostfwd=tcp::10022-:22 \
#                      -enable-kvm -cpu host
#
# once the kernel boots, you can ssh into it with:
#
#   ssh -o StrictHostKeyChecking=no -p 10022 root@localhost
#

set -eux

NAME="rootfs.ext4"
FORMAT="ext4"
RESIZER="resize2fs"
SIZE="1G"
IMAGE="amazonlinux:2023"

# Display help function
display_help() {
    echo "Usage: $0 [option...] " >&2
    echo
    echo "   -f, --format               rootfs format (ext4 or xfs), default ext4"
    echo "   -h, --help                 Display help message"
    echo "   -n, --name                 rootfs name, default rootfs.ext4"
    echo "   -s, --size                 rootfs size, default 1G"
    echo
}

while true; do
    if [ $# -eq 0 ]; then
        break
    fi
    case "$1" in
        -h | --help)
            display_help
            exit 0
            ;;
        -f | --format)
            FORMAT=$2
            shift 2

            case "${FORMAT}" in
                ext4)
                    RESIZER="resize2fs"
                    ;;
                xfs)
                    RESIZER="xfs_growfs"
                    ;;
                -*)
                    echo "Error Unknown format: ${FORMAT}" >&2
                    exit 1
                    ;;
            esac
            ;;
        -n | --name)
            NAME=$2
            shift 2
            ;;
        -s | --size)
            SIZE=$2
            shift 2
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

MOUNT_DIR=$(mktemp -d)

if [ -f "${NAME}" ]; then
    truncate -s ${SIZE} ${NAME}
    sudo mount -o loop ${NAME} ${MOUNT_DIR}
    sudo ${RESIZER} /dev/loop0
    sudo umount ${MOUNT_DIR}
    rm -r ${MOUNT_DIR}
    exit 0;
fi

truncate -s ${SIZE} ${NAME}
mkfs.${FORMAT} ${NAME}
sudo mount -o loop ${NAME} ${MOUNT_DIR}

REMOVE_IMAGE=false
if [[ "$(sudo docker images -q ${IMAGE} 2>/dev/null)" == "" ]]; then
    REMOVE_IMAGE=true
fi

CONTAINER=$(sudo docker create ${IMAGE})
sudo docker export ${CONTAINER} | sudo tar -xC ${MOUNT_DIR}
sudo docker rm ${CONTAINER}

if "${REMOVE_IMAGE}" ; then
    sudo docker rmi ${IMAGE}
fi

sudo cp /etc/resolv.conf ${MOUNT_DIR}/etc/resolv.conf

sudo chroot ${MOUNT_DIR} sh -c "
dnf install -y \
    systemd systemd-networkd systemd-resolved systemd-udev \
    openssh-server passwd strace

systemctl enable systemd-networkd

cat << EOF > /etc/systemd/network/ether.network
[Match]
Driver=e1000

[Network]
DHCP=yes
EOF

rm /etc/resolv.conf

sed -i -e 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' \
     -e 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' \
     /etc/ssh/sshd_config

passwd -d root
"

sudo umount ${MOUNT_DIR}
rm -r ${MOUNT_DIR}
