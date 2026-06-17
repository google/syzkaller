#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Sanity tests for binaries in built Docker images.
# Run this after build.sh.

set -e
TAG_PREFIX="gcr.io/syzkaller"

test_image() {
  local image=$1
  local cmd=$2
  echo "=== Testing $image ==="
  echo "Command: $cmd"
  # Run bash with the command
  docker run --rm "$image" -c "$cmd"
  echo "Success!"
  echo ""
}

# ------------------------------------------
# env:base
# ------------------------------------------
test_image "${TAG_PREFIX}/env:base" "go version"
test_image "${TAG_PREFIX}/env:base" "clang --version"
test_image "${TAG_PREFIX}/env:base" "git --version"
test_image "${TAG_PREFIX}/env:base" "flatc --version"
test_image "${TAG_PREFIX}/env:base" "bindgen --version"

# ------------------------------------------
# env:arch
# ------------------------------------------
test_image "${TAG_PREFIX}/env:arch" "arm-linux-gnueabi-gcc --version"
test_image "${TAG_PREFIX}/env:arch" "aarch64-linux-gnu-gcc --version"
test_image "${TAG_PREFIX}/env:arch" "riscv64-linux-gnu-gcc --version"

# ------------------------------------------
# env:dashboard
# ------------------------------------------
test_image "${TAG_PREFIX}/env:dashboard" "gcloud --version"
test_image "${TAG_PREFIX}/env:dashboard" "/spanner/gateway_main --help > /dev/null"

# ------------------------------------------
# env:latest (full)
# ------------------------------------------
test_image "${TAG_PREFIX}/env:latest" "rustc --version"
test_image "${TAG_PREFIX}/env:latest" "node --version"

# ------------------------------------------
# syzbot
# ------------------------------------------
test_image "${TAG_PREFIX}/syzbot:latest" "bazel --version"
test_image "${TAG_PREFIX}/syzbot:latest" "/opt/bin/strace -V"
test_image "${TAG_PREFIX}/syzbot:latest" "qemu-system-x86_64 --version"
test_image "${TAG_PREFIX}/syzbot:latest" "clang-15 --version"
test_image "${TAG_PREFIX}/syzbot:latest" "gcloud --version"
test_image "${TAG_PREFIX}/syzbot:latest" "rustc --version"
