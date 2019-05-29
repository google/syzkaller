#!/bin/bash

# This script provides utility functions, don't use it directly.

set -eux

THISDIR=`cd $(dirname $0); pwd`

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit

function util_add_syzbot_bits {
  scripts/kconfig/merge_config.sh .config $SYZBOT_CONFIG
  # Not merged in for some reason.
  scripts/config -e CONFIG_KCOV_ENABLE_COMPARISONS
  make CC="${CC}" olddefconfig
}

function util_add_usb_bits {
  MERGE_USB_SCRIPT=${THISDIR}/kconfiglib-merge-usb-configs.py

  git clone --depth=1 https://github.com/ulfalizer/Kconfiglib.git
  wget -qO- https://raw.githubusercontent.com/ulfalizer/Kconfiglib/master/makefile.patch | patch -p1
  for config in ${THISDIR}/distros/*; do
    make CC="${CC}" scriptconfig SCRIPT=${MERGE_USB_SCRIPT} SCRIPT_ARG=${config}
  done
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
}

function util_add_syzbot_extra_bits {
  echo "# The following configs are added manually, preserve them.
# CONFIG_DEBUG_MEMORY was once added to mm tree and cause disabling of KASAN,
# which in turn caused storm of assorted crashes after silent memory
# corruptions. The config was reverted, but we keep it here for the case
# it is reintroduced to kernel again.
CONFIG_DEBUG_MEMORY=y
# This config can be used to enable any additional temporal debugging
# features in linux-next tree.
CONFIG_DEBUG_AID_FOR_SYZBOT=y
" > $1
}
