#!/bin/bash
# Copyright 2019 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

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
util_add_syzbot_bits aux-debug

util_add_syzbot_extra_bits

cp .config ${OUTPUT_CONFIG}
