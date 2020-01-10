#!/bin/bash
# Copyright 2019 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Generate upstream-kmsan.config from upstream-kasan.config.
# Make sure $CC points to the Clang binary and $KERNEL_SOURCE - to the kernel tree.

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit
[ -z "${KERNEL_SOURCE}" ] && echo 'Please set $KERNEL_SOURCE to point to the kernel tree!' && exit

THIS_DIR=`cd $(dirname $0); pwd`
. ${THIS_DIR}/util.sh

KASAN_CONFIG=${THIS_DIR}/upstream-kasan.config
KMSAN_CONFIG=${THIS_DIR}/upstream-kmsan.config
KMSAN_ADD=${THIS_DIR}/bits-kmsan.config

cd ${KERNEL_SOURCE}

cp ${KASAN_CONFIG} .config
scripts/kconfig/merge_config.sh -m .config ${KMSAN_ADD}
make ${MAKE_VARS} olddefconfig

util_add_usb_bits
util_add_syzbot_extra_bits

cp .config ${KMSAN_CONFIG}
