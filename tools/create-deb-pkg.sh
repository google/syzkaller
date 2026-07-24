#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Build a .deb package for syzkaller.
#
# Usage:
#   tools/create-deb-pkg.sh [--arch ARCH]
#
# Options:
#   --arch ARCH   Target architecture (amd64, arm64). Default: host arch.
#
# This script expects to be run from the syzkaller source root.
# Binaries must already be built in bin/ (e.g. via 'make' or syz-env).
#
# Example workflow:
#   tools/syz-env make                    # build inside container
#   tools/create-deb-pkg.sh              # package on host
#
#   tools/syz-env make TARGETARCH=arm64 HOSTARCH=arm64  # cross-build
#   tools/create-deb-pkg.sh --arch arm64

set -euo pipefail

ARCH=$(dpkg --print-architecture)

while [[ $# -gt 0 ]]; do
	case "$1" in
		--arch) ARCH="${2:?Error: --arch requires an argument}"; shift 2;;
		*) echo "Unknown option: $1" >&2; exit 1;;
	esac
done

cd "$(dirname "$0")/.."

if ! command -v dpkg-buildpackage >/dev/null 2>&1; then
	echo "Error: dpkg-buildpackage is not installed. Please install dpkg-dev and debhelper." >&2
	exit 1
fi

if [[ ! -d bin ]]; then
	echo "Error: bin/ directory not found. Build syzkaller first:" >&2
	echo "  make  (or: tools/syz-env make)" >&2
	exit 1
fi

VERSION="0.0~git$(date +%Y%m%d).$(git rev-parse --short HEAD)-1"
MAINTAINER="${DEBEMAIL:-syzkaller <syzkaller@googlegroups.com>}"

trap 'rm -f debian/changelog' EXIT

printf "syzkaller (%s) unstable; urgency=medium\n\n  * Snapshot from git %s\n\n -- %s  %s\n" \
	"$VERSION" "$(git rev-parse --short HEAD)" "$MAINTAINER" "$(date -R)" > debian/changelog

dpkg-buildpackage -us -uc -b -d -a "$ARCH"

echo ""
echo "Package built: ../syzkaller_${VERSION}_${ARCH}.deb"
