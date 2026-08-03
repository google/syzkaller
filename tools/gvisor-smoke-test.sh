#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -xeuo pipefail

workdir="$(mktemp -d /tmp/syzkaller-gvisor-test.XXXXXX)"

cleanup() {
  rm -rf "$workdir"
}

trap cleanup EXIT

# Setup coverage directory if requested
if [[ -n "${SyzCoverDir:-}" ]]; then
  mkdir -p "${SyzCoverDir}"
  export GOCOVERDIR="$(cd "${SyzCoverDir}" && pwd)"
fi

syzdir="$(pwd)"
cat > "$workdir/config" <<EOF
{
        "name": "gvisor",
        "target": "linux/amd64",
        "http": ":54321",
        "workdir": "$workdir/workdir",
        "image": "$workdir/kernel/vmlinux",
        "kernel_obj": "$workdir/kernel/",
        "syzkaller": "$syzdir",
        "cover": false,
        "procs": 1,
        "type": "gvisor",
        "vm": {
                "count": 1,
                "runsc_args": "--ignore-cgroups --network none --rootless"
        }
}
EOF

mkdir "$workdir/kernel"
if [[ -z "${GVISOR_VMLINUX_PATH:-}" ]]; then
  arch="$(uname -m)"
  url="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}"
  curl --output "$workdir/kernel/vmlinux" "${url}/runsc"
  chmod a+rx "$workdir/kernel/vmlinux"
else
  install -m555 "$GVISOR_VMLINUX_PATH" "$workdir/kernel/vmlinux"
fi

./bin/syz-manager -config "$workdir/config" --mode smoke-test

if [[ -n "${GOCOVERDIR:-}" ]]; then
  if [[ -n "${SyzCoverProfile:-}" ]]; then
    if ls "${GOCOVERDIR}"/covmeta.* >/dev/null 2>&1; then
      go tool covdata textfmt -i="${GOCOVERDIR}" -o="${SyzCoverProfile}"
    else
      echo "No coverage data found in ${GOCOVERDIR}"
    fi
  fi
fi
