#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Exit on any problem.
set -e
set -o pipefail

if [ -z "$1" ];then
    echo "Pass LLVM version in the argument."
    exit 1
fi

LLVM_VERSION=$1

url="https://mirrors.edge.kernel.org/pub/tools/llvm/files"
tmp=$(mktemp -d)
cd $tmp

# Download the archive.
curl -L $url/$LLVM_VERSION.tar.gz -o $LLVM_VERSION.tar.gz

# LLVM archive intergrity check.
curl -L -s $url/sha256sums.asc | grep $LLVM_VERSION.tar.gz > $LLVM_VERSION.asc
sha256sum -c $LLVM_VERSION.asc

# GPG signature import.
curl -L -s $url/$LLVM_VERSION.tar.sign -o $LLVM_VERSION.tar.sign
keyid=$(gpg --list-packets $LLVM_VERSION.tar.sign | grep -oE "keyid .*$" | awk '{print $2}')
gpg --keyserver keyserver.ubuntu.com --recv-keys $keyid
# See https://www.kernel.org/signature.html
gpg --tofu-policy good $keyid

# Decompress & gpg signature verification.
gunzip -d $LLVM_VERSION.tar
gpg --trust-model tofu --verify $LLVM_VERSION.tar.sign $LLVM_VERSION.tar

# Untar binaries to the output.
tar -xf $LLVM_VERSION.tar --strip-components=2 -C /usr/bin $LLVM_VERSION/bin

cd -
rm -rf $tmp