#!/bin/bash

set -eux

THISDIR=`cd $(dirname $0); pwd`

SYZBOT_CONFIG=${THISDIR}/bits-syzbot.config
DISTRO_CONFIG=${THISDIR}/distros/ubuntu-bionic-config-4.15.0-47-generic
USB_CONFIG=${THISDIR}/upstream-usb.config
MERGE_USB_SCRIPT=${THISDIR}/kconfiglib-merge-usb-configs.py
. ${THISDIR}/util.sh

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit
[ -z "${SOURCEDIR}" ] && echo 'Please set $SOURCEDIR to point to the kernel tree!' && exit

cd ${SOURCEDIR}
make CC="${CC}" defconfig
make CC="${CC}" kvmconfig

util_add_usb_bits

scripts/kconfig/merge_config.sh .config $SYZBOT_CONFIG

sed -i "s#=m\$#=y#g" .config

# Not merged in for some reason.
scripts/config -e CONFIG_KCOV_ENABLE_COMPARISONS

sed -i "s#=m\$#=y#g" .config
make CC="${CC}" olddefconfig

util_add_extra_syzbot_configs "${USB_CONFIG}"

cat .config >> ${USB_CONFIG}
cp ${USB_CONFIG} .config
