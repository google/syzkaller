#!/bin/bash

set -eux

THISDIR=`cd $(dirname $0); pwd`

SYZBOT_CONFIG=${THISDIR}/bits-syzbot.config
DISTRO_CONFIG=${THISDIR}/distros/ubuntu-bionic-config-4.15.0-47-generic
USB_CONFIG=${THISDIR}/upstream-usb.config
MERGE_USB_SCRIPT=${THISDIR}/kconfiglib-merge-usb-configs.py

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit
[ -z "${SOURCEDIR}" ] && echo 'Please set $SOURCEDIR to point to the kernel tree!' && exit

cd $SOURCEDIR

make CC="${CC}" defconfig
make CC="${CC}" kvmconfig

git clone --depth=1 https://github.com/ulfalizer/Kconfiglib.git
wget -qO- https://raw.githubusercontent.com/ulfalizer/Kconfiglib/master/makefile.patch | patch -p1
make CC="${CC}" scriptconfig SCRIPT=${MERGE_USB_SCRIPT} SCRIPT_ARG=$DISTRO_CONFIG
git checkout ./scripts/kconfig/Makefile
rm -rf ./Kconfiglib

scripts/config -d CONFIG_USB_CONFIGFS
scripts/config -d CONFIG_USB_LIBCOMPOSITE

scripts/config -d CONFIG_USB_G_NCM
scripts/config -d CONFIG_USB_G_SERIAL
scripts/config -d CONFIG_USB_G_PRINTER
scripts/config -d CONFIG_USB_G_NOKIA
scripts/config -d CONFIG_USB_G_ACM_MS
scripts/config -d CONFIG_USB_G_MULTI
scripts/config -d CONFIG_USB_G_HID
scripts/config -d CONFIG_USB_G_DBGP
scripts/config -d CONFIG_USB_G_WEBCAM

scripts/config -e CONFIG_USB_GADGET
scripts/config -e CONFIG_USB_GADGETFS
scripts/config -e CONFIG_USB_DUMMY_HCD
scripts/config -e CONFIG_USB_FUZZER

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
