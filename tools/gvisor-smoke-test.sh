#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -xeuo pipefail

workdir="$(mktemp -d /tmp/syzkaller-gvisor-test.XXXXXX)"

cleanup() {
  sudo -E rm -rf "$workdir"
}

trap cleanup EXIT

syzdir="$(pwd)"
cat > "$workdir/config" <<EOF
{
        "name": "gvisor",
        "target": "linux/amd64",
        "http": ":54321",
        "workdir": "/$workdir/workdir/",
        "image": "$workdir/kernel/vmlinux",
        "kernel_obj": "$workdir/kernel/",
        "syzkaller": "$syzdir",
        "cover": false,
        "procs": 1,
        "type": "gvisor",
        "vm": {
                "count": 1,
                "runsc_args": "--ignore-cgroups --network none"
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

sudo -E ./bin/syz-manager -config "$workdir/config" --mode smoke-test
