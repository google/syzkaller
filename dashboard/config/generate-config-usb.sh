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

echo "# The following configs are added manually, preserve them.
# CONFIG_DEBUG_MEMORY was once added to mm tree and cause disabling of KASAN,
# which in turn caused storm of assorted crashes after silent memory
# corruptions. The config was reverted, but we keep it here for the case
# it is reintroduced to kernel again.
CONFIG_DEBUG_MEMORY=y
# This config can be used to enable any additional temporal debugging
# features in linux-next tree.
CONFIG_DEBUG_AID_FOR_SYZBOT=y
" > ${USB_CONFIG}

cat .config >> ${USB_CONFIG}
cp ${USB_CONFIG} .config
