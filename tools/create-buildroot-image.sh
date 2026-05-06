#!/usr/bin/env bash
# Copyright 2021 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# This script builds a buildroot-based Linux image.
# It should be run from a buildroot checkout (git://git.buildroot.net/buildroot) as:
# TARGETARCH={amd64,arm64,arm,riscv64,s390x,mips64le,ppc64le} [NOMAKE=yes] create-buildroot-image.sh
# If no NOMAKE=yes is specified, then it will just prepare the buildroot config,
# but will not run the final make.
# For amd64 and arm64 it creates a bootable image with root partition
# on /dev/sda1 in output/images/disk.img file.
# For other architectures it creates a non-bootable disk
# suitable qemu injected boot with root partition on /dev/sda
# in output/images/rootfs.ext4 file.
# Note: the image requires at least kernel v4.19
# (otherwise glibc complains about unsupported kernel version).

set -eux

NOMAKE="${NOMAKE:-}"
TARGETARCH="${TARGETARCH:-amd64}"
LINUX_VERSION="${LINUX_VERSION:-6.18.6}"
LINUX_KERNEL_CONFIG="${LINUX_KERNEL_CONFIG:-$(pwd)/../dashboard/config/linux/upstream-kexec.config}"

case "$TARGETARCH" in
	amd64)
		DEFCONFIG="pc_x86_64_bios_defconfig";;
	arm64)
		DEFCONFIG="aarch64_efi_defconfig";;
	arm)
		DEFCONFIG="qemu_arm_vexpress_defconfig";;
	riscv64)
		DEFCONFIG="qemu_riscv64_virt_defconfig";;
	s390x)
		DEFCONFIG="qemu_s390x_defconfig";;
	mips64le)
		DEFCONFIG="qemu_mips64r6el_malta_defconfig";;
	ppc64le)
		DEFCONFIG="qemu_ppc64le_pseries_defconfig";;
	*)
		echo "unsupported TARGETARCH=${TARGETARCH}"
		exit 1;;
esac

git fetch origin
git checkout 2025.02.1

make "${DEFCONFIG}"

# Common configs for all architectures.
cat >>.config <<EOF
BR2_TARGET_GENERIC_HOSTNAME="syzkaller"
BR2_TARGET_GENERIC_ISSUE="syzkaller"
BR2_ROOTFS_POST_FAKEROOT_SCRIPT="./rootfs_script.sh"
BR2_TOOLCHAIN_BUILDROOT_GLIBC=y
BR2_PACKAGE_DHCPCD=y
BR2_PACKAGE_OPENSSH=y
BR2_PACKAGE_MAKEDUMPFILE=y
BR2_PACKAGE_KEXEC=y

# This slows down boot.
# BR2_PACKAGE_URANDOM_SCRIPTS is not set

BR2_TARGET_ROOTFS_EXT2_SIZE="1G"
# Slightly more interesting and realistic options.
BR2_TARGET_ROOTFS_EXT2_MKFS_OPTIONS="-O 64bit,ext_attr,encrypt,extents,huge_file,flex_bg,dir_nlink,sparse_super,resize_inode,has_journal"

# Install firmware for USB devices we can connect during fuzzing.
BR2_PACKAGE_LINUX_FIRMWARE=y
BR2_PACKAGE_LINUX_FIRMWARE_MEDIATEK_MT7650=y
BR2_PACKAGE_LINUX_FIRMWARE_MEDIATEK_MT7601U=y
BR2_PACKAGE_LINUX_FIRMWARE_MEDIATEK_MT7610E=y
BR2_PACKAGE_LINUX_FIRMWARE_MEDIATEK_MT76X2E=y
BR2_PACKAGE_LINUX_FIRMWARE_AR3012_USB=y
BR2_PACKAGE_LINUX_FIRMWARE_BRCM_BCM43XX=y
BR2_PACKAGE_LINUX_FIRMWARE_BRCM_BCM43XXX=y
BR2_PACKAGE_LINUX_FIRMWARE_LIBERTAS_USB8388_V9=y
BR2_PACKAGE_LINUX_FIRMWARE_LIBERTAS_USB8388_OLPC=y
BR2_PACKAGE_LINUX_FIRMWARE_LIBERTAS_USB_THINFIRM=y
BR2_PACKAGE_LINUX_FIRMWARE_MWIFIEX_USB8797=y
BR2_PACKAGE_LINUX_FIRMWARE_MWIFIEX_USB8801=y
BR2_PACKAGE_LINUX_FIRMWARE_MWIFIEX_USB8897=y
BR2_PACKAGE_LINUX_FIRMWARE_RALINK_RT61=y
BR2_PACKAGE_LINUX_FIRMWARE_RALINK_RT73=y
BR2_PACKAGE_LINUX_FIRMWARE_RALINK_RT2XX=y
BR2_PACKAGE_LINUX_FIRMWARE_AS102=y
BR2_PACKAGE_LINUX_FIRMWARE_DIB0700=y
BR2_PACKAGE_LINUX_FIRMWARE_ITETECH_IT9135=y
BR2_PACKAGE_LINUX_FIRMWARE_CX231XX=y
BR2_PACKAGE_LINUX_FIRMWARE_QUALCOMM_WIL6210=y
# This one we could use, but it breaks buildroot:
# Makefile.legacy:9: *** You have legacy configuration in your .config! Please check your configuration.
# BR2_PACKAGE_LINUX_FIRMWARE_ATHEROS_10K_QCA6174=y
BR2_PACKAGE_LINUX_FIRMWARE_ATHEROS_10K_QCA998X=y
BR2_PACKAGE_LINUX_FIRMWARE_ATHEROS_10K_QCA9377=y
BR2_PACKAGE_ZD1211_FIRMWARE=y

# These packages seem to enable rfkill (and are unnecessary).
# BR2_PACKAGE_CONNMAN is not set
# BR2_PACKAGE_WPA_SUPPLICANT is not set

# These packages enable SELinux policy.
BR2_PACKAGE_LIBSELINUX=y
BR2_PACKAGE_REFPOLICY=y
BR2_PACKAGE_REFPOLICY_POLICY_STATE_PERMISSIVE=y
# BR2_PACKAGE_REFPOLICY_POLICY_STATE_ENFORCING is not set
# BR2_PACKAGE_REFPOLICY_POLICY_STATE_DISABLED is not set
EOF

# Per-arch config fragments.
case "$TARGETARCH" in
        amd64)
		cat >>.config <<EOF
BR2_TARGET_GENERIC_GETTY_PORT="ttyS0"
BR2_LINUX_KERNEL_USE_ARCH_DEFAULT_CONFIG=y
BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES="board/qemu/x86_64/linux.config"
# This is used to create some device links in devfs (see udev rules below),
# but this is too slow for emulated architectures.
BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_EUDEV=y
BR2_LINUX_KERNEL_CUSTOM_VERSION=y
BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="${LINUX_VERSION}"
BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE="${LINUX_KERNEL_CONFIG}"
BR2_LINUX_KERNEL_INSTALL_TARGET=y
BR2_KERNEL_HEADERS_5_10=y
BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_5_10=y
EOF
;;
        arm64)
                cat >>.config <<EOF
BR2_cortex_a57=y
BR2_LINUX_KERNEL_USE_ARCH_DEFAULT_CONFIG=y
BR2_LINUX_KERNEL_IMAGEGZ=y
BR2_LINUX_KERNEL_GZIP=y
BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_5_10=y
BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="5.10.235"
BR2_ROOTFS_POST_IMAGE_SCRIPT="board/aarch64-efi/post-image.sh ./post_image_script.sh support/scripts/genimage.sh"
BR2_ROOTFS_POST_SCRIPT_ARGS="-c ./custom-genimage-efi.cfg"
EOF
;;
	arm)
		cat >>.config <<EOF
# BR2_LINUX_KERNEL is not set
BR2_cortex_a15_a7=y
BR2_TARGET_ROOTFS_EXT2_4=y
EOF
;;
	s390x)
		cat >>.config <<EOF
# BR2_LINUX_KERNEL is not set
EOF
;;
	mips64le)
		cat >>.config <<EOF
# BR2_LINUX_KERNEL is not set
EOF
;;
	ppc64le)
		cat >>.config <<EOF
# BR2_LINUX_KERNEL is not set
EOF
;;
	riscv64)
		cat >>.config <<EOF
# BR2_LINUX_KERNEL is not set
EOF
;;
esac

# Set syslogd level to "critical", otherwise we may get too many unrelated logs (see #5452).
sed -i 's/SYSLOGD_ARGS=""$/SYSLOGD_ARGS="-l 2"/' package/busybox/S01syslogd

# dhcpd version 10.1.0 fails to start in the presence of CONFIG_SECCOMP.
sed -i 's/DHCPCD_VERSION = 10.1.0$/DHCPCD_VERSION = 10.2.0/' package/dhcpcd/dhcpcd.mk
if ! grep -q "dhcpcd-10.2.0.tar.xz" package/dhcpcd/dhcpcd.hash; then
  echo "sha256 7916fed1560835b5b9d70d27604c3858e501c5a177eef027f96eb7ab0f711399 dhcpcd-10.2.0.tar.xz" >> package/dhcpcd/dhcpcd.hash
fi

# This script modifies the target root filesystem
# before it's packed into the final image.
# This part is common for all architectures.
cat >rootfs_script.sh <<'EOFEOF'
set -eux

# Mount /dev right after / is mounted.
sed -Ei '/\/dev\/pts/i ::sysinit:/bin/mount -t devtmpfs devtmpfs /dev' $1/etc/inittab

# Mount debugfs for KCOV and other filesystems.
cat >>$1/etc/fstab <<EOF
debugfs /sys/kernel/debug debugfs defaults 0 0
securityfs /sys/kernel/security securityfs defaults 0 0
configfs /sys/kernel/config/ configfs defaults 0 0
binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0
smackfs /sys/fs/smackfs smackfs defaults 0 0
selinuxfs /sys/fs/selinux selinuxfs defaults 0 0
fusectl /sys/fs/fuse/connections fusectl defaults 0 0
pstore /sys/fs/pstore pstore defaults 0 0
bpf /sys/fs/bpf bpf defaults 0 0
tracefs /sys/kernel/tracing tracefs defaults 0 0
EOF

# Setup ssh without key/password.
cat >$1/etc/ssh/sshd_config <<EOF
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
ClientAliveInterval 420
Subsystem	sftp	/usr/libexec/sftp-server
EOF

# Generate sshd host keys.
env -u LD_LIBRARY_PATH ssh-keygen -A -f $1
mkdir -p $1/var/db/dhcpcd

EOFEOF

# Per-arch part of the rootfs script.
case "$TARGETARCH" in
	amd64)
cat >>rootfs_script.sh <<'EOFEOF'

# Write udev rules.
cat >$1/etc/udev/rules.d/50-syzkaller.rules <<EOF
ATTR{name}=="vim2m", SYMLINK+="vim2m"
SUBSYSTEMS=="pci", DRIVERS=="i915", SYMLINK+="i915"
EOF

if [ -f $1/boot/bzImage ]; then
    mv $1/boot/bzImage $1/boot/bzImageKexec
else
    echo "DEBUG: /boot/bzImage not found in \$1"
    ls -R $1/boot || echo "/boot directory does not exist"
fi

# Override default grub config with timeout 0.
cat >$1/boot/grub/grub.cfg <<EOF
set default="0"
set timeout="0"
menuentry "syzkaller" {
	linux /boot/bzImage root=/dev/sda1 console=ttyS0
}
EOF
EOFEOF
;;
        arm64)
cat >post_image_script.sh <<'EOFEOF'
cat >${BINARIES_DIR}/efi-part/EFI/BOOT/grub.cfg <<EOF
set default="0"
set timeout="0"
menuentry "syzkaller" {
	linux /Image.gz root=PARTLABEL=root enforcing=0 console=ttyS0
}
EOF
EOFEOF
;;
esac

# Adjust consts in buildroot source files.
case "$TARGETARCH" in
  arm64)
    cp board/aarch64-efi/genimage-efi.cfg custom-genimage-efi.cfg
    # 64 MB is too small for our large images.
    sed -i 's/size = 64M/size = 256M/g' custom-genimage-efi.cfg
    # Also, use compressed images.
    sed -i 's/Image/Image.gz/g' custom-genimage-efi.cfg
    ;;
esac

touch post_image_script.sh  # only created for some archs
chmod u+x rootfs_script.sh post_image_script.sh

make olddefconfig

if [[ "$NOMAKE" == "" ]]; then
	make
fi
