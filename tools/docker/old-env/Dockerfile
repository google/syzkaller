# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# See /tools/docker/README.md for details.

FROM ubuntu:16.04

LABEL homepage="https://github.com/google/syzkaller"

RUN dpkg --add-architecture i386 && apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
	sudo make nano git curl ca-certificates gnupg \
	apt-transport-https software-properties-common g++ \
	g++-arm-linux-gnueabi g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu \
	g++-mips64el-linux-gnuabi64 g++-s390x-linux-gnu \
	linux-libc-dev:i386 lib32gcc-5-dev lib32stdc++-5-dev \
	&& \
	apt-get -y autoremove && \
	apt-get clean autoclean && \
	rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

RUN curl https://dl.google.com/go/go1.20.11.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/go/bin:/gopath/bin:$PATH
ENV GOPATH /gopath

# Install clang-12 from llvm.org.
# The distro-provided clang is too old for Go fuzzing.
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-12 main"
RUN apt-get update
RUN apt-get install -y -q --no-install-recommends clang-12
RUN ln -s /usr/bin/clang-12 /usr/bin/clang

# Pre-create dirs for syz-env.
# This is necessary to make docker work with the current user,
# otherwise --volume will create these dirs under root and then
# the current user won't have access to them.
RUN mkdir -p /syzkaller/gopath/src/github.com/google/syzkaller && \
	mkdir -p /syzkaller/.cache && \
	chmod -R 0777 /syzkaller

# The default Docker prompt is too ugly and takes the whole line:
# I have no name!@0f3331d2fb54:~/gopath/src/github.com/google/syzkaller$
RUN echo "export PS1='syz-old-env⌛ '" > /syzkaller/.bashrc
ENV SYZ_OLD_ENV yes

ENTRYPOINT ["bash"]
