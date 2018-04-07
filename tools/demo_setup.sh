#!/bin/bash
# Copyright 2018 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# This script setups everything that's needed to run syzkaller
# using qemu on known working syzkaller/kernel revisions.
# Tested on Ubuntu 16.04 and Debian rolling. The script downloads a bunch
# of stuff, so make sure you have a good internet connection.
# But first ensure that you have KVM enabled in BIOS and in kernel,
# otherwise fuzzing will be very slow and lots of things will time out, see:
# https://help.ubuntu.com/community/KVM/Installation
# https://www.linux-kvm.org/page/FAQ
# If everything goes successfully, the script will start syz-manager
# that will start fuzzing Linux kernel. You should see periodic log lines
# of the following form:
# 2018/04/01 10:00:00 VMs 10, executed 50170, cover 42270, crashes 0, repro 0
# syz-manager web UI contains a summary of crashes:
# http://localhost:20000
# You can always abort syz-manager with Ctrl+C and start it again by running
# the last command of this script.

set -eux

export DIR=$PWD
export PATH=$DIR/go/bin:$PATH
export GOPATH=$DIR/gopath
export GOROOT=
export NVM=$(((`free -g | grep "Mem:" | awk '{print $2}'`-1)/3))

sudo apt-get install -y -q make git curl bison flex bc libssl-dev gcc g++ qemu-system-x86

curl https://dl.google.com/go/go1.10.1.linux-amd64.tar.gz | tar -xz
curl https://storage.googleapis.com/syzkaller/gcc-7.tar.gz | tar -xz
curl https://storage.googleapis.com/syzkaller/corpus.db.tar.gz | tar -xz
wget https://storage.googleapis.com/syzkaller/wheezy.img
wget https://storage.googleapis.com/syzkaller/wheezy.img.key
chmod 0600 wheezy.img.key
mkdir workdir
mv corpus.db workdir/

go get -d github.com/google/syzkaller/...
(cd $GOPATH/src/github.com/google/syzkaller; \
    git checkout ad7d294798bac1b8da37cf303e44ade90689bb1c; \
    make; \
)

git clone --branch v4.13 --single-branch --depth=1 \
	git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
curl https://gist.githubusercontent.com/dvyukov/2c63231d1cd0d162ac6bebb4627f045c/raw/c3d5c80d391ba4853d6a6453db38c249f40b4b8b/gistfile1.txt > linux/.config
(cd linux; make -j32 CC=$DIR/gcc/bin/gcc)

cat <<'EOF' | sed "s#DIR#$DIR#g" | sed "s#NVM#$NVM#g" > config
{
    "name": "demo",
    "target": "linux/amd64",
    "http": ":20000",
    "workdir": "DIR/workdir",
    "vmlinux": "DIR/linux/vmlinux",
    "syzkaller": "DIR/gopath/src/github.com/google/syzkaller",
    "image": "DIR/wheezy.img",
    "sshkey": "DIR/wheezy.img.key",
    "sandbox": "none",
    "procs": 8,
    "type": "qemu",
    "vm": {
        "count": NVM,
        "cpu": 4,
        "mem": 2048,
        "kernel": "DIR/linux/arch/x86/boot/bzImage"
    }
}
EOF

gopath/src/github.com/google/syzkaller/bin/syz-manager -config config
