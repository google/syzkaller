# Copyright 2021 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# syzbot container is used to run syz-ci on syzbot, use as:
# docker build -t gcr.io/syzkaller/syzbot tools/docker/syzbot
# docker push gcr.io/syzkaller/syzbot
# docker run -it gcr.io/syzkaller/syzbot

FROM debian:bullseye

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
	# Build essentials:
	gcc g++ binutils make ccache bazel-bootstrap golang-go \
	clang clang-format clang-tidy \
	# Some common utilities:
	unzip curl sudo procps psmisc nano vim git bzip2 dh-autoreconf software-properties-common \
	# These are needed to build Linux kernel:
	flex bison bc gawk dwarves cpio texinfo texi2html lzop lbzip2 \
	zlib1g-dev libelf-dev libncurses-dev libmpc-dev libssl-dev \
	# This is required to run alien arch binaries in pkg/cover tests:
	qemu-user \
	# These are required to run foreign arch kernels:
	qemu-utils qemu-system-misc qemu-system-x86 qemu-system-arm qemu-system-aarch64  \
	qemu-system-s390x qemu-system-mips qemu-system-ppc \
	# Cross-compilation:
	g++-arm-linux-gnueabi g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu \
	g++-mips64el-linux-gnuabi64 g++-s390x-linux-gnu g++-riscv64-linux-gnu \
	libc6-dev-i386 libc6-dev-i386-amd64-cross lib32gcc-10-dev lib32stdc++-10-dev

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd syzkaller
RUN echo "export PS1='\n\W🤖 '" >> /root/.bashrc
