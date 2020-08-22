# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# The image provides dev environment suitable for syzkaller development/testing.
# It includes Go toolchain and C/C++ cross-compilers.

# The image is available as gcr.io/syzkaller/old-env.

# To download and run locally:
#	docker pull gcr.io/syzkaller/old-env
#	docker run -it gcr.io/syzkaller/old-env

# To build and push new version:
#	docker build -t gcr.io/syzkaller/old-env tools/docker/old-env
#	gcloud auth login && gcloud auth configure-docker
#	docker push gcr.io/syzkaller/old-env

FROM ubuntu:16.04

LABEL homepage="https://github.com/google/syzkaller"

RUN dpkg --add-architecture i386 && \
	apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
	sudo make nano git curl ca-certificates g++ \
	g++-arm-linux-gnueabi g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu \
	g++-mips64el-linux-gnuabi64 g++-s390x-linux-gnu \
	linux-libc-dev:i386 lib32gcc-5-dev lib32stdc++-5-dev \
	&& \
	apt-get -y autoremove && \
	apt-get clean autoclean && \
	rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

RUN curl https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/go/bin:/gopath/bin:$PATH
ENV GOPATH /gopath

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
