#!/bin/bash
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Post-build validation for syzkaller binaries.

target_os="$1"; shift
target_arch="$1"; shift
executor_binary="$1"; shift
cxx_binary="$1"; shift

function get_objdump_for_arm64() {
  local compiler_binary="$1"
  local objdump_binary=""

  case "${compiler_binary}" in
    "aarch64-linux-gnu-g++")
      objdump_binary="aarch64-linux-gnu-objdump"
      ;;
    "g++")
      objdump_binary="objdump"
      ;;
    clang++-[0-9]*)
      # Extract the version number part
      version="${compiler_binary#clang++-}"
      objdump_binary="llvm-objdump-$version"
      ;;
    "clang++")
      objdump_binary="llvm-objdump"
      ;;
    *)
      # Default
      echo "Error: Unknown compiler binary '${compiler_binary}'" >&2
      objdump_binary=""
      ;;
  esac

  echo "${objdump_binary}"
}

function validate_arm64_guest_code() {
  local section="guest"
  local objdump_bin=$(get_objdump_for_arm64 ${cxx_binary})
  local objdump_tmp=$(mktemp -t objdump_output.XXXXXX)
  trap "rm -f \"${objdump_tmp}\"" EXIT
  ${objdump_bin} -d -j ${section} ${executor_binary} >${objdump_tmp} 2>&1 || exit 1
  ( cat ${objdump_tmp} | grep "\<adrp\>" > /dev/null ) &&
    echo "Postbuild error: found ADRP in executor's '${section}' section!" && exit 1
  return 0
}

# For now, we only validate Linux binaries.
[ "${target_os}" != "linux" ] && exit 0

# For now, we only validate ARM64 binaries.
[ "${target_arch}" != "arm64" ] && exit 0

validate_arm64_guest_code
