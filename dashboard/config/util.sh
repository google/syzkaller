#!/bin/bash
# Copyright 2019 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# This script provides utility functions, don't use it directly.

set -eux

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit

THIS_DIR=`cd "${BASH_SOURCE[0]}"; pwd`
MAKE_VARS="CC=${CC}"

function util_add_syzbot_bits {
  scripts/kconfig/merge_config.sh -m .config ${THIS_DIR}/bits-syzbot.config
  if [ "$#" == "1" ]; then
    if [ "$1" == "aux-debug" ]; then
      scripts/kconfig/merge_config.sh -m .config ${THIS_DIR}/bits-syzbot-aux-debug.config
    fi
  fi
  # Fix up config.
  make ${MAKE_VARS} olddefconfig
  # syzbot does not support modules.
  sed -i "s#=m\$#=y#g" .config
  # Fix up configs that can only be modules.
  make ${MAKE_VARS} olddefconfig
}

function util_add_usb_bits {
  MERGE_USB_SCRIPT=${THIS_DIR}/kconfiglib-merge-usb-configs.py

  git clone --depth=1 https://github.com/ulfalizer/Kconfiglib.git
  wget -qO- https://raw.githubusercontent.com/ulfalizer/Kconfiglib/master/makefile.patch | patch -p1

  prefix=""
  if [ "$#" == "1" ]; then
    prefix="$1"
  fi
  configs=""
  for config in ${THIS_DIR}/distros/${prefix}*; do
    configs+="${config},"
  done
  make ${MAKE_VARS} scriptconfig SCRIPT=${MERGE_USB_SCRIPT} SCRIPT_ARG=${configs}
  git checkout ./scripts/kconfig/Makefile
  rm -rf ./Kconfiglib

  scripts/config -d CONFIG_USB_G_NCM
  scripts/config -d CONFIG_USB_G_SERIAL
  scripts/config -d CONFIG_USB_G_PRINTER
  scripts/config -d CONFIG_USB_G_NOKIA
  scripts/config -d CONFIG_USB_G_ACM_MS
  scripts/config -d CONFIG_USB_G_MULTI
  scripts/config -d CONFIG_USB_G_HID
  scripts/config -d CONFIG_USB_G_DBGP
  scripts/config -d CONFIG_USB_G_WEBCAM

  scripts/config -d CONFIG_USB_ZERO
  scripts/config -d CONFIG_USB_AUDIO
  scripts/config -d CONFIG_USB_ETH
  scripts/config -d CONFIG_USB_FUNCTIONFS
  scripts/config -d CONFIG_USB_MASS_STORAGE
  scripts/config -d CONFIG_USB_GADGET_TARGET
  scripts/config -d CONFIG_USB_MIDI_GADGET
  scripts/config -d CONFIG_USB_CDC_COMPOSITE

  scripts/config -d CONFIG_USB_GADGETFS
  scripts/config -d CONFIG_USB_LIBCOMPOSITE
  scripts/config -d CONFIG_USB_CONFIGFS
  
  scripts/config -e CONFIG_USB_GADGET
  scripts/config -e CONFIG_USB_DUMMY_HCD
  scripts/config -e CONFIG_USB_RAW_GADGET

  make ${MAKE_VARS} olddefconfig
}

function util_add_syzbot_extra_bits {
  TMP_FILE=$(mktemp /tmp/syzkaller.XXXXXX)
  echo "# The following configs are added manually, preserve them.
# CONFIG_DEBUG_MEMORY was once added to mm tree and cause disabling of KASAN,
# which in turn caused storm of assorted crashes after silent memory
# corruptions. The config was reverted, but we keep it here for the case
# it is reintroduced to kernel again.
CONFIG_DEBUG_MEMORY=y
# This config can be used to enable any additional temporal debugging
# features in linux-next tree.
CONFIG_DEBUG_AID_FOR_SYZBOT=y
# These configs can be used to prevent fuzzers from trying stupid things.
# See https://github.com/google/syzkaller/issues/1622 for details.
CONFIG_TWIST_KERNEL_BEHAVIOR=y
CONFIG_TWIST_FOR_SYZKALLER_TESTING=y
" > ${TMP_FILE}
  cat .config >> ${TMP_FILE}
  mv ${TMP_FILE} .config
  rm -rf ${TMP_FILE}
}
