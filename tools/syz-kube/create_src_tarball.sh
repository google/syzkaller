#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e

TMP_DIR="/tmp/syz-src"
TARBALL="syzkaller_src.tar.gz"

echo "Preparing source temp directory..."
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

# Copy root files
cp Makefile go.mod go.sum "$TMP_DIR/"

# Copy essential directories
cp -r pkg executor sys prog "$TMP_DIR/"
mkdir -p "$TMP_DIR/dashboard"
cp -r dashboard/dashapi "$TMP_DIR/dashboard/"

# Copy tools (excluding heavy stuff)
mkdir -p "$TMP_DIR/tools"
cp -r tools/* "$TMP_DIR/tools/"
rm -rf "$TMP_DIR/tools/docker"
rm -rf "$TMP_DIR/tools/syz-kube/bin"

# Copy essential binaries
mkdir -p "$TMP_DIR/bin/linux_amd64"
cp bin/syz-bisect bin/syz-manager bin/syz-hub "$TMP_DIR/bin/"
cp bin/linux_amd64/syz-execprog bin/linux_amd64/syz-executor "$TMP_DIR/bin/linux_amd64/"

# Copy assets (only SSH keys)
mkdir -p "$TMP_DIR/assets"
cp assets/id_rsa assets/id_rsa.pub "$TMP_DIR/assets/"

echo "Creating tarball $TARBALL..."
tar -czf "$TARBALL" -C "$TMP_DIR" .

echo "Cleaning up temp directory..."
rm -rf "$TMP_DIR"

echo "Tarball created successfully: $TARBALL (size: $(du -sh $TARBALL | cut -f1))"
