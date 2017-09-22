#!/usr/bin/env bash
# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Assuming x86 host, you also need to install:
# sudo apt-get install gcc-aarch64-linux-gnu gcc-powerpc64le-linux-gnu gcc-arm-linux-gnueabihf

set -eu

if [ "$LINUX" == "" ]; then
	if [ "$ANDROID" == "" ]; then
		echo "usage: make extract LINUX=/linux/checkout]"
		echo "OR: make extract ANDROID=/linux/checkout]"
		exit 1
	else
		LINUX=$ANDROID
		BUILD_FOR_ANDROID=yes
	fi
else
	BUILD_FOR_ANDROID=no
fi

UPSTREAM_FILES="bpf.txt dri.txt fuse.txt input.txt ipc.txt
		key.txt kvm.txt loop.txt perf.txt random.txt
		sndcontrol.txt sndseq.txt sndtimer.txt
		sys.txt test.txt tty.txt tun.txt vnet.txt
		socket.txt socket_alg.txt socket_bluetooth.txt
		socket_inet.txt socket_inet6.txt socket_inet_tcp.txt
		socket_inet_udp.txt socket_inet_icmp.txt
		socket_inet_sctp.txt socket_inet_dccp.txt
		socket_kcm.txt socket_key.txt socket_netlink.txt
		socket_netrom.txt socket_nfc.txt socket_unix.txt
		socket_ipx.txt socket_ax25.txt socket_llc.txt
		socket_packet.txt xattr.txt"

ANDROID_FILES="tlk_device.txt ion.txt"

if [ "$BUILD_FOR_ANDROID" == "no" ]; then
	ARCHES=""
	FILES="$UPSTREAM_FILES"
else
	ARCHES="amd64,arm64"
	FILES="$ANDROID_FILES"
fi

(cd sys/linux; ../../bin/syz-extract -build -arch "$ARCHES" -linux "$LINUX" $FILES)
