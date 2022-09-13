# Copyright 2021 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# syzbot container is used to run syz-ci on syzbot, use as:
# docker build -t gcr.io/syzkaller/syzbot tools/docker/syzbot
# docker push gcr.io/syzkaller/syzbot
# docker run -it gcr.io/syzkaller/syzbot

FROM debian:bullseye

RUN apt-get update --allow-releaseinfo-change
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
	# Build essentials:
	gcc g++ binutils make ccache \
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
	libc6-dev-i386 libc6-dev-i386-amd64-cross lib32gcc-10-dev lib32stdc++-10-dev \
	apt-transport-https curl gnupg python-is-python3 \
	# Needed for building Cuttlefish images.
	rsync libarchive-tools

RUN curl https://dl.google.com/go/go1.17.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/go/bin:$PATH

# The default clang-11 is too old, install the latest one.
RUN apt-get install -y -q gnupg software-properties-common apt-transport-https
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-13 main"
RUN apt-get update --allow-releaseinfo-change
RUN apt-get remove -y -q clang-11
RUN apt-get install -y -q --no-install-recommends clang-13 clang-format-13 clang-tidy-13
RUN apt autoremove -y -q
RUN sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-13 100
RUN sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-13 100
RUN sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-13 100
RUN sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-13 100

# Download and install the custom Clang required to build KMSAN.
# TODO(@ramosian-glider): switch to stable Clang once KMSAN is upstreamed.
ENV CLANG_KMSAN_VER 610139d2d9ce
RUN curl https://storage.googleapis.com/syzkaller/clang-${CLANG_KMSAN_VER}.tar.gz | tar -C /usr/local/ -xz
RUN ln -s /usr/local/clang-${CLANG_KMSAN_VER} /usr/local/clang-kmsan

# Not really GRTE, but it's enough to run some scripts that hardcode the path.
RUN mkdir -p /usr/grte/v5/bin && ln -s /usr/bin/python3 /usr/grte/v5/bin/python2.7

# Install bazel
RUN echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" | \
	sudo tee /etc/apt/sources.list.d/bazel.list && \
	curl https://bazel.build/bazel-release.pub.gpg | sudo apt-key add -
RUN apt-get update --allow-releaseinfo-change && DEBIAN_FRONTEND=noninteractive apt-get install -y -q bazel

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller
RUN echo "export PS1='\n\W🤖 '" >> /root/.bashrc
