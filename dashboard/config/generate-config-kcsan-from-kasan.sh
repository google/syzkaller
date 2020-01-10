#!/bin/bash
# Copyright 2019 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Generate upstream-kcsan.config from upstream-kasan.config.

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit
[ -z "${KERNEL_SOURCE}" ] && echo 'Please set $KERNEL_SOURCE to point to the kernel tree!' && exit

THIS_DIR=`cd $(dirname $0); pwd`
. ${THIS_DIR}/util.sh

KASAN_CONFIG=${THIS_DIR}/upstream-kasan.config
KCSAN_CONFIG=${THIS_DIR}/upstream-kcsan.config
KCSAN_ADD=${THIS_DIR}/bits-kcsan.config

cd ${KERNEL_SOURCE}

cp ${KASAN_CONFIG} .config
scripts/kconfig/merge_config.sh -m .config ${KCSAN_ADD}
make ${MAKE_VARS} olddefconfig

util_add_syzbot_extra_bits

cp .config ${KCSAN_CONFIG}
