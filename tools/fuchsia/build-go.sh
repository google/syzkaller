#!/bin/bash

# This script can be used to compile Go for fuchsia.
# You need to have a fuchsia checkout defined in the FX_SRC_PATH variable,
# The fuchsia sdk in the FX_SDK_PATH variable, and a CLANG compatible with
# fuchsia in CLANG_PATH.

if [[ -z ${FX_SDK_PATH} ]]; then
  echo "FX_SDK_PATH variable not set"
  exit 1
fi

if [[ -z ${FX_SRC_PATH} ]]; then
  echo "FX_SRC_PATH variable not set"
  exit 1
fi

if [[ -z ${CLANG_PATH} ]]; then
  echo "CLANG_PATH variable not set"
  exit 1
fi

cd "${FX_SRC_PATH}/third_party/go/src"

FUCHSIA_SHARED_LIBS=${FX_SDK_PATH}/arch/x64/lib \
  CLANG_PREFIX=${CLANG_PATH}/bin \
  FDIO_INCLUDE=${FX_SDK_PATH}/pkg/fdio/include \
  ZIRCON_SYSROOT=${FX_SDK_PATH}/arch/x64/sysroot \
  CC=${FX_SRC_PATH}/third_party/go/misc/fuchsia/clangwrap.sh \
  CGO_ENABLED=1 \
  GOOS=fuchsia \
  ./make.bash
