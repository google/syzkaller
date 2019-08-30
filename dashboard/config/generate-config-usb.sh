#!/bin/bash

set -eux

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit
[ -z "${KERNEL_SOURCE}" ] && echo 'Please set $KERNEL_SOURCE to point to the kernel tree!' && exit

THIS_DIR=`cd $(dirname $0); pwd`
. ${THIS_DIR}/util.sh

OUTPUT_CONFIG=${THIS_DIR}/upstream-usb.config

cd ${KERNEL_SOURCE}

make ${MAKE_VARS} defconfig
make ${MAKE_VARS} kvmconfig

util_add_usb_bits
util_add_syzbot_bits

sed -i "s#=m\$#=y#g" .config
make ${MAKE_VARS} olddefconfig

util_add_syzbot_extra_bits

cp .config ${OUTPUT_CONFIG}
