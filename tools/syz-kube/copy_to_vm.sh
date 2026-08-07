#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e
MINIKUBE="./tools/syz-kube/bin/minikube -p syzkube"
TARBALL="syzkaller_src.tar.gz"

if [ ! -f "$TARBALL" ]; then
  echo "Error: $TARBALL not found. Run ./tools/syz-kube/create_src_tarball.sh first."
  exit 1
fi

echo "Creating directories in VM..."
$MINIKUBE ssh "sudo rm -rf /syzkaller && sudo mkdir -p /syzkaller && sudo chown -R docker:docker /syzkaller"

echo "Copying disk.raw..."
$MINIKUBE cp disk.raw /syzkaller/disk.raw

echo "Copying and extracting source tarball..."
$MINIKUBE cp "$TARBALL" /syzkaller/"$TARBALL"
$MINIKUBE ssh "tar -xf /syzkaller/$TARBALL -C /syzkaller && rm -f /syzkaller/$TARBALL"

echo "Setting permissions..."
$MINIKUBE ssh "chmod 600 /syzkaller/assets/id_rsa && chmod 644 /syzkaller/assets/id_rsa.pub"
$MINIKUBE ssh "chmod +x /syzkaller/bin/* && chmod +x /syzkaller/bin/linux_amd64/*"

echo "Copy complete."
