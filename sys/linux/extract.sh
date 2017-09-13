#!/usr/bin/env bash
# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Assuming x86 host, you also need to install:
# sudo apt-get install gcc-aarch64-linux-gnu gcc-powerpc64le-linux-gnu gcc-arm-linux-gnueabihf

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
	FILES="$UPSTREAM_FILES"
else
	FILES="$ANDROID_FILES"
fi

generate_arch() {
	echo generating arch $1...
	echo "cd $LINUX; make defconfig"
	OUT=`(cd $LINUX; make ARCH=$2 CROSS_COMPILE=$3 CFLAGS=$4 defconfig 2>&1)`
	if [ $? -ne 0 ]; then
		echo "$OUT"
		exit 1
	fi
	# Without CONFIG_NETFILTER kernel does not build.
	(cd $LINUX; sed -i "s@# CONFIG_NETFILTER is not set@CONFIG_NETFILTER=y@g" .config)
	(cd $LINUX; make ARCH=$2 CROSS_COMPILE=$3 CFLAGS=$4 olddefconfig)
	echo "cd $LINUX; make"
	OUT=`(cd $LINUX; make ARCH=$2 CROSS_COMPILE=$3 CFLAGS=$4 init/main.o 2>&1)`
	if [ $? -ne 0 ]; then
		echo "$OUT"
		exit 1
	fi
	(cd sys/linux; ../../bin/syz-extract -arch $1 -linux "$LINUX" -linuxbld "$LINUXBLD" $FILES)
	if [ $? -ne 0 ]; then
		exit 1
	fi
	echo
}

# $1 Go arch
# $2 kernel arch
# $3 cross-compiler prefix
# $4 CLAGS
generate_arch amd64 x86_64 x86_64-linux-gnu- "-m64"
generate_arch arm64 arm64 aarch64-linux-gnu- ""
if [ "$BUILD_FOR_ANDROID" == "no" ]; then
	generate_arch 386 i386 "" "-m32"
	generate_arch arm arm arm-linux-gnueabihf- "-march=armv6t2"
	generate_arch ppc64le powerpc powerpc64le-linux-gnu- ""
fi
