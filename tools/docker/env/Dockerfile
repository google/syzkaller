# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# See /tools/docker/README.md for details.

FROM debian:bullseye

LABEL homepage="https://github.com/google/syzkaller"

RUN apt-get update --allow-releaseinfo-change
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
	sudo make python nano git curl ca-certificates binutils g++ \
	g++-arm-linux-gnueabi g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu \
	g++-mips64el-linux-gnuabi64 g++-s390x-linux-gnu g++-riscv64-linux-gnu \
	libc6-dev-i386 libc6-dev-i386-amd64-cross lib32gcc-10-dev lib32stdc++-10-dev \
	# These are needed to build Linux kernel:
	flex bison bc libelf-dev libssl-dev \
	# qemu-user is required to run alien arch binaries in pkg/cover tests.
	qemu-user \
	&& \
	apt-get -y autoremove && \
	apt-get clean autoclean && \
	rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

RUN curl https://dl.google.com/go/go1.17.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/go/bin:/gopath/bin:$PATH
ENV GOPATH /gopath

# Pre-create dirs for syz-dock.
# This is necessary to make docker work with the current user,
# otherwise --volume will create these dirs under root and then
# the current user won't have access to them.
RUN mkdir -p /syzkaller/gopath/src/github.com/google/syzkaller && \
	mkdir -p /syzkaller/.cache && \
	chmod -R 0777 /syzkaller

# The default clang-11 is too old, install the latest one.
RUN apt-get install -y -q gnupg software-properties-common apt-transport-https
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-15 main"
RUN apt-get update --allow-releaseinfo-change
RUN apt-get remove -y -q clang-11
RUN apt-get install -y -q --no-install-recommends clang-15 clang-format-15 clang-tidy-15
RUN apt autoremove -y -q
RUN sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 100
RUN sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-15 100
RUN sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-15 100
RUN sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-15 100

# The default Docker prompt is too ugly and takes the whole line:
# I have no name!@0f3331d2fb54:~/gopath/src/github.com/google/syzkaller$
RUN echo "export PS1='syz-env🈴 '" > /syzkaller/.bashrc
ENV SYZ_ENV yes

ENTRYPOINT ["bash"]
