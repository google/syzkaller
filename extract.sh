#!/usr/bin/env bash
# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

if [ "$LINUX" == "" ]; then
	echo "usage: make extract LINUX=/linux/checkout]"
	exit 1
fi

FILES="sys/sys.txt sys/socket.txt sys/tty.txt sys/perf.txt sys/kvm.txt \
	sys/key.txt sys/bpf.txt sys/fuse.txt sys/dri.txt sys/kdbus.txt sys/sctp.txt \
	sys/sndseq.txt sys/sndtimer.txt sys/sndcontrol.txt sys/input.txt \
	sys/netlink.txt sys/tun.txt sys/random.txt sys/kcm.txt sys/netrom.txt"

generate_arch() {
	echo generating arch $1...
	echo "cd $LINUX; make defconfig"
	OUT=`(cd $LINUX; make ARCH=$2 CROSS_COMPILE=/usr/bin/$3-linux-gnu- defconfig 2>&1)`
	if [ $? -ne 0 ]; then
		echo "$OUT"
		exit 1
	fi
	echo "cd $LINUX; make"
	OUT=`(cd $LINUX; make ARCH=$2 CROSS_COMPILE=/usr/bin/$3-linux-gnu- init/main.o 2>&1)`
	if [ $? -ne 0 ]; then
		echo "$OUT"
		exit 1
	fi
	for F in $FILES; do
		echo "extracting from $F"
		bin/syz-extract -arch $1 -linux "$LINUX" -linuxbld "$LINUXBLD" $F
		if [ $? -ne 0 ]; then
			exit 1
		fi
	done
	echo
}

generate_arch amd64 x86_64 x86_64
generate_arch arm64 arm64 aarch64
generate_arch ppc64le powerpc powerpc64le
