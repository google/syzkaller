#!/bin/bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# See https://source.android.com/setup/build/building-kernels
# for details on how to checkout and build Android kernel.

set -eux

SRC_DIR=$1
VERSION=$2
KERNEL_SOURCE="$SRC_DIR/common"
DEFCONFIG="$KERNEL_SOURCE/arch/x86/configs/gki_defconfig"
SCRIPT_DIR=`cd $(dirname $0); pwd`

function usage {
	echo "usage: generate.sh /android/kernel/checkout/dir kernel.version"
	echo "supported kernel versions: 5.4"
	exit 1
}

if [ ! -e "$DEFCONFIG" ]; then
	usage
fi

case "$VERSION" in
	5.4)
		CC="$SRC_DIR/prebuilts-master/clang/host/linux-x86/clang-r370808/bin/clang"
		;;
	*)
		usage
esac

. ${SCRIPT_DIR}/../util.sh
cd ${KERNEL_SOURCE}
cp $DEFCONFIG .config

util_add_usb_bits "android"
util_add_syzbot_bits

scripts/kconfig/merge_config.sh -m .config ${SCRIPT_DIR}/config-bits
make ${MAKE_VARS} olddefconfig

cp .config ${SCRIPT_DIR}/config-$VERSION
