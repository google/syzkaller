#!/usr/bin/env bash
# Copyright 2023 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# First follow the tutorial at https://fuchsia.dev/fuchsia-src/get-started/build_fuchsia
# Set the following env variables before executing this script:
# SYZKALLER -- path to the syzkaller checkout.
# FUCHSIA -- path to the fuchsia checkout.
# SDK -- where the generated sdk should be stored.


if [ -z "${SYZKALLER}" ]; then
  echo "The SYZKALLER environment variable is not set."
  exit 1
fi

if [ -z "${FUCHSIA}" ]; then
  echo "The FUCHSIA environment variable is not set."
  exit 1
fi

if [ -z "${SDK}" ]; then
  echo "The SDK environment variable is not set."
  exit 1
fi

# Copy generic SDK files.

function copy_dir() {
    FROM=${1}
    TO=${2}
    FLAGS=${3}
    if [ -z "$FLAGS" ]
    then
      FLAGS="-rL"
    fi
    mkdir -p ${TO}
    echo "Copying ${FLAGS} ${FROM}/. to ${TO}"
    cp ${FLAGS} ${FROM}/. ${TO}
}

mkdir -p $SDK

# Build and copy arm64 files.

cd ${FUCHSIA}

SYZKALLER_ARG=\"${SYZKALLER}\"
fx --dir "out/arm64" set core.arm64 \
  --with-base "//bundles/tools" \
  --with-base "//src/testing/fuzzing/syzkaller" \
  --args=syzkaller_dir="${SYZKALLER_ARG}" \
  --variant=kasan

fx build

for folder in out/arm64/fidling/gen out/arm64/arm64-shared; do
  copy_dir ${FUCHSIA}/${folder} ${SDK}/${folder}
done
copy_dir ${FUCHSIA}/out/arm64/sdk/exported/zircon_sysroot/arch/arm64/sysroot ${SDK}/out/arm64/sysroot

# Build and copy x64 files.

fx --dir "out/x64" set core.x64 \
  --with-base "//bundles/tools" \
  --with-base "//src/testing/fuzzing/syzkaller" \
  --args=syzkaller_dir="${SYZKALLER_ARG}" \
  --variant=kasan

fx build

for folder in out/x64/fidling/gen out/x64/x64-shared; do
  copy_dir ${FUCHSIA}/${folder} ${SDK}/${folder}
done
copy_dir ${FUCHSIA}/out/x64/sdk/exported/zircon_sysroot/arch/x64/sysroot ${SDK}/out/x64/sysroot

# Copy common files.

for folder in sdk/lib src/lib zircon; do
  copy_dir ${FUCHSIA}/${folder} ${SDK}/${folder}
done
copy_dir ${FUCHSIA}/prebuilt/third_party/clang ${SDK}/prebuilt/third_party/clang "-r --preserve=links"
