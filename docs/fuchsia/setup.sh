#!/usr/bin/env bash

# Copyright 2022 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -o errexit
set -o errtrace
set -o nounset
set -o pipefail
shopt -s extdebug
IFS=$'\n\t'

# TODO: Make the workdir be a parameter.
# TODO: Scope locals, pass more things as parameters.
# TODO: This script is getting overgrown enough that it's probably time start
# using Go instead.

help="This script will set up, build, and run Syzkaller for Fuchsia. You will
need a Syzkaller checkout and a Fuchsia checkout, and you will need a working
installation of the Go programming language. See docs/fuchsia/README.md in the
Syzkaller repository for more information.

In the commands below, \`syzkaller-directory\` and \`fuchsia-directory\` must be
absolute pathnames.

Usage:

  setup.sh help

Prints this help message.

  setup.sh build syzkaller-directory fuchsia-directory

Builds Syzkaller and Fuchsia for x64.

  setup.sh [-d] run syzkaller-directory fuchsia-directory

Runs Syzkaller on the Fuchsia emulator. (You must have built both first, using
\`setup.sh build ...\`.) If you pass the \`-d\` option, \`syz-manager\` will be
run with the \`--debug\` option.

  setup.sh update syzkaller-directory fuchsia-directory

Updates the Fuchsia system call definitions that Syzkaller will use."

die() {
  echo "$@" > /dev/stderr
  echo "For help, run \`setup.sh help\`."
  exit 1
}

usage() {
  echo "$help"
  exit 0
}

preflight() {
  if ! which go > /dev/null; then
    die "You need to install the Go language."
  fi

  syzkaller="$1"
  if [[ ! -d "$syzkaller" ]]; then
    die "$syzkaller is not a directory."
  fi
  fuchsia="$2"
  if [[ ! -d "$fuchsia" ]]; then
    die "$fuchsia is not a directory."
  fi
}

build() {
  preflight "$syzkaller" "$fuchsia"

  cd "$fuchsia"
  fx --dir "out/x64" set core.x64 \
    --with-base "//bundles/tools" \
    --with-base "//src/testing/fuzzing/syzkaller" \
    --args=syzkaller_dir="\"$syzkaller\"" \
    --variant=kasan
  fx build

  cd "$syzkaller"
  make TARGETOS=fuchsia TARGETARCH=amd64 SOURCEDIR="$fuchsia"
}

run() {
  preflight "$syzkaller" "$fuchsia"

  cd "$fuchsia"

  product_bundle_path="$(ffx config get product.path | tr -d '"')"
  # Look up needed deps from the product bundle assembled
  fxfs_path="$(ffx product get-image-path "$product_bundle_path" --slot a --image-type fxfs)"
  zbi_path="$(ffx product get-image-path "$product_bundle_path" --slot a --image-type zbi)"
  multiboot_path="$(ffx product get-image-path "$product_bundle_path" --slot a --image-type qemu-kernel)"

  # Make sure there are ssh keys available
  ffx config check-ssh-keys
  auth_keys_path="$(ffx config get ssh.pub | tr -d '"')"
  priv_key_path="$(ffx config get ssh.priv | tr -d '"')"

  # Make a separate directory for copies of files we need to modify
  syz_deps_path=$fuchsia/out/x64/syzdeps
  mkdir -p "$syz_deps_path"

  ./out/x64/host_x64/zbi -o "${syz_deps_path}/fuchsia-ssh.zbi" "${zbi_path}" \
    --entry "data/ssh/authorized_keys=${auth_keys_path}"

  cp "$fxfs_path" "${syz_deps_path}/fxfs.blk"

  echo "{
  \"name\": \"fuchsia\",
  \"target\": \"fuchsia/amd64\",
  \"http\": \":12345\",
  \"workdir\": \"$workdir\",
  \"kernel_obj\": \"$fuchsia/out/x64/kernel_x64-kasan/obj/zircon/kernel\",
  \"syzkaller\": \"$syzkaller\",
  \"image\": \"$syz_deps_path/fxfs.blk\",
  \"sshkey\": \"$priv_key_path\",
  \"reproduce\": false,
  \"cover\": false,
  \"procs\": 8,
  \"type\": \"qemu\",
  \"vm\": {
    \"count\": 10,
    \"cpu\": 4,
    \"mem\": 2048,
    \"kernel\": \"$multiboot_path\",
    \"initrd\": \"$syz_deps_path/fuchsia-ssh.zbi\"
  }
}" > "$workdir/fx-syz-manager-config.json"

  cd "$syzkaller"
  # TODO: Find the real way to fix this: Syzkaller wants to invoke qemu
  # manually, but perhaps it should be calling `ffx emu ...` or the like. See
  # also //scripts/hermetic-env and //tools/devshell/lib/prebuilt.sh in
  # $fuchsia.
  PATH="$PATH:$fuchsia/prebuilt/third_party/qemu/linux-x64/bin:$fuchsia/prebuilt/third_party/qemu/mac-x64/bin"
  bin/syz-manager -config "$workdir/fx-syz-manager-config.json" "$debug"
}

update_syscall_definitions() {
  # TODO
  echo "NOTE: This command does not currently work."
  exit

  preflight "$syzkaller" "$fuchsia"

  cd "$syzkaller"
  make extract TARGETOS=fuchsia SOURCEDIR="$fuchsia"
  make generate
}

main() {
  debug=""
  while getopts "d" o; do
    case "$o" in
    d)
      debug="--debug" ;;
    *) ;;
    esac
  done
  shift $((OPTIND - 1))

  if [[ $# != 3 ]]; then
    usage
  fi

  command="$1"
  syzkaller="$2"
  fuchsia="$3"
  workdir="$syzkaller/workdir.fuchsia"
  mkdir -p "$workdir"

  case "$command" in
    build)
      build;;
    run)
      run;;
    update)
      update_syscall_definitions;;
    *)
      usage;;
  esac
}

main "$@"
