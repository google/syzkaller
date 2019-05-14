#!/bin/bash

# This script provides utility functions, don't use it directly.

set -eux

THISDIR=`cd $(dirname $0); pwd`

[ -z "${CC}" ] && echo 'Please set $CC to point to the compiler!' && exit

function util_add_usb_bits {

  DISTRO_CONFIG=${THISDIR}/distros/ubuntu-bionic-config-4.15.0-47-generic
  MERGE_USB_SCRIPT=${THISDIR}/kconfiglib-merge-usb-configs.py

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
}
