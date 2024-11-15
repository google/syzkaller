#!/usr/bin/env bash

# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# The script assumes that there exist workdir_net and workdir_fs folders with networking and fs corpuses correspondingly.

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <first_linux_repo> <second_linux_repo> <image_path>"
  exit 1
fi

BASE_KERNEL="$1"
PATCHED_KERNEL="$2"
IMAGE_PATH="$3"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
BASE_DIR=$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")

KERNEL_CONFIG="$(mktemp)"
wget -q -O "$KERNEL_CONFIG" 'https://raw.githubusercontent.com/google/syzkaller/master/dashboard/config/linux/upstream-apparmor-kasan.config'

patch_config_file() {
  FILE="$1"
  KERNEL_PATH="$2"
  sed -i "s|%KERNEL%|$KERNEL_PATH|g" "$FILE"
  sed -i "s|%SYZKALLER%|$BASE_DIR|g" "$FILE"
  sed -i "s|%IMAGE%|$IMAGE_PATH|g" "$FILE"
}

run_experiment() {
  GUILTY_COMMIT="$1"
  TYPE="$2"
  TITLE="$3"

  PATCHED_CONFIG="$SCRIPT_DIR/patched_$TYPE.cfg"
  PATCHED_WORKDIR="$BASE_DIR/workdir_$TYPE"

  echo "--------"
  date
  echo "COMMIT: $GUILTY_COMMIT"
  echo "TITLE: $TITLE"

  echo "Building the base kernel"
  (
    cd "$BASE_KERNEL"
    git clean -fxfd
    git reset --hard "$GUILTY_COMMIT"
    git revert "$GUILTY_COMMIT" --no-edit
    cp "$KERNEL_CONFIG" .config
    make CC=clang LD=ld.lld olddefconfig
    make CC=clang LD=ld.lld -j32
  ) >/dev/null 2>&1

  echo "Building the patched kernel"
  (
    cd "$PATCHED_KERNEL"
    git clean -fxfd
    git reset --hard "$GUILTY_COMMIT"
    cp "$KERNEL_CONFIG" .config
    make CC=clang LD=ld.lld olddefconfig
    make CC=clang LD=ld.lld -j32
  ) >/dev/null 2>&1

  WORKDIR_NAME="experiment/$(date +"%Y-%m-%d_%H-%M-%S")_$GUILTY_COMMIT"
  mkdir -p "$WORKDIR_NAME"
  WORKDIR_PATH=$(realpath "$WORKDIR_NAME")
  echo "COMMIT: $GUILTY_COMMIT" > "$WORKDIR_PATH/description.txt"
  echo "TITLE: $TITLE" >> "$WORKDIR_PATH/description.txt"
  echo "WORKDIR: $WORKDIR_NAME"
  (
    cd "$BASE_KERNEL"
    git show "$GUILTY_COMMIT" > "$WORKDIR_PATH/patch.diff"
  )
  # Prepare syzkaller configs.
  cp base.cfg "$WORKDIR_PATH/"
  patch_config_file "$WORKDIR_PATH/base.cfg" "$BASE_KERNEL"
  cp "$PATCHED_CONFIG" "$WORKDIR_PATH/patched.cfg"
  patch_config_file "$WORKDIR_PATH/patched.cfg" "$PATCHED_KERNEL"
  rm -rf "$PATCHED_WORKDIR/crashes"

  (
    cd "$WORKDIR_PATH"
    timeout 3h "$BASE_DIR/bin/syz-diff" -base base.cfg -new patched.cfg -patch patch.diff -vv 1 2>&1 | tee "log.log" | grep "patched-only"
  )
  cp -r "$PATCHED_WORKDIR/crashes" "$WORKDIR_PATH"
}

run_experiment 17194be4c8e1 net "general protection fault in ethnl_phy_doit"
run_experiment d18d3f0a24fc net "KASAN: slab-use-after-free Read in l2tp_tunnel_del_work"
run_experiment 181a42edddf5 net "WARNING in hci_conn_del"
run_experiment 401cb7dae813 net "stack segment fault in cpu_map_redirect"
run_experiment 186b1ea73ad8 net "kernel BUG in dev_gro_receive"
run_experiment af0cb3fa3f9e net "KASAN: slab-use-after-free Read in htab_map_alloc"
run_experiment f7a8b10bfd61 net "WARNING in rdev_scan"
run_experiment 948dbafc15da net "KASAN: global-out-of-bounds Read in __nla_validate_parse"
run_experiment c3718936ec47 net "WARNING: suspicious RCU usage in in6_dump_addrs"

run_experiment 94a69db2367e fs "possible deadlock in xfs_ilock"
run_experiment 275dca4630c1 fs "KASAN: slab-use-after-free Read in kill_f2fs_super"
run_experiment 16aac5ad1fa9 fs "general protection fault in ovl_encode_real_fh"
run_experiment b5357cb268c4 fs "KASAN: slab-out-of-bounds Read in btrfs_qgroup_inherit"
run_experiment 310ee0902b8d fs "WARNING in ext4_iomap_begin"
run_experiment 744a56389f73 fs "WARNING in __fortify_report"
run_experiment c3defd99d58c fs "divide error in ext4_mb_regular_allocator"
run_experiment 11a347fb6cef fs "kernel BUG in iov_iter_revert"
run_experiment 0586d0a89e77 fs "kernel BUG in btrfs_folio_end_all_writers"
