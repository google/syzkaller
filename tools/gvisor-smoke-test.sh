#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -xeuo pipefail

workdir="$(mktemp -d /tmp/syzkaller-gvisor-test.XXXXXX)"

cleanup() {
  while sudo -E umount "$workdir/workdir/gvisor_root/null-netns" 2>/dev/null; do true; done
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
        "image": "$workdir/kernel/image",
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
if [[ -z "${GVISOR_TARBALL_PATH:-}" ]]; then
  arch="$(uname -m)"
  url="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}"
  curl --fail --location --output "$workdir/gvisor.tar.bz2" "${url}/gvisor.tar.bz2"
  curl --fail --location --output "$workdir/gvisor.tar.bz2.sha512" "${url}/gvisor.tar.bz2.sha512"
  (cd "$workdir" && sha512sum -c gvisor.tar.bz2.sha512)
  mv "$workdir/gvisor.tar.bz2" "$workdir/kernel/image"
else
  cp "$GVISOR_TARBALL_PATH" "$workdir/kernel/image"
fi

sudo -E ./bin/syz-manager -config "$workdir/config" --mode smoke-test
