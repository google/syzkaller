#!/bin/bash

set -eux

THISDIR=`cd $(dirname $0); pwd`

SYZBOT_CONFIG=${THISDIR}/bits-syzbot.config
USB_CONFIG=${THISDIR}/upstream-usb.config
. ${THISDIR}/util.sh

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit
[ -z "${SOURCEDIR}" ] && echo 'Please set $SOURCEDIR to point to the kernel tree!' && exit

cd ${SOURCEDIR}
make CC="${CC}" defconfig
make CC="${CC}" kvmconfig

util_add_usb_bits
util_add_syzbot_bits

sed -i "s#=m\$#=y#g" .config
make CC="${CC}" olddefconfig

util_add_syzbot_extra_bits "${USB_CONFIG}"

cat .config >> ${USB_CONFIG}
cp ${USB_CONFIG} .config
