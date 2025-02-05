# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# See /tools/docker/README.md for details.

# Build Python2 in a separate container to facilitate caching.
FROM debian:bookworm AS python2-builder

RUN apt-get update --allow-releaseinfo-change
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    wget gcc make openssl libffi-dev libgdbm-dev libsqlite3-dev libssl-dev zlib1g-dev ca-certificates
RUN wget -O /tmp/Python-2.7.18.tgz 'https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz'
RUN cd /tmp/ && tar -zxf Python-2.7.18.tgz
RUN cd /tmp/Python-2.7.18 && ./configure --prefix=/python2/
RUN cd /tmp/Python-2.7.18 && make -j4 && make altinstall

# Construct a /syzkaller folder.
FROM debian:bookworm as syzkaller-folder
WORKDIR /syzkaller
RUN apt-get update --allow-releaseinfo-change
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q curl

# Pre-create dirs for syz-dock.
# This is necessary to make docker work with the current user,
# otherwise --volume will create these dirs under root and then
# the current user won't have access to them.
RUN mkdir -p /syzkaller/gopath/src/github.com/google/syzkaller && \
	mkdir -p /syzkaller/.cache/gomod && \
	chmod -R 0777 /syzkaller

# Install OS toolchains from pre-built archives.
# These archives were created with:
# tar -cz --owner=0 --group=0 --mode=go=u -f netbsd-toolchain.tar.gz netbsd/tools netbsd/dest
# tar -cz --owner=0 --group=0 --mode=go=u -f fuchsia-toolchain.tar.gz fuchsia/prebuilt/third_party/clang \
#	fuchsia/zircon/system/ulib fuchsia/src/lib/ddk fuchsia/out/x64/fidling/gen \
#	fuchsia/out/x64/zircon_toolchain/obj/zircon/public/sysroot/sysroot \
#	fuchsia/out/x64/x64-shared/*.so fuchsia/out/arm64/fidling/gen \
#	fuchsia/out/arm64/zircon_toolchain/obj/zircon/public/sysroot/sysroot \
#	fuchsia/out/arm64/arm64-shared/*.so
#
# And then uploaded to GCS with:
# gsutil mv gs://syzkaller/GOOS-toolchain.tar.gz gs://syzkaller/GOOS-toolchain.old.tar.gz
# gsutil cp GOOS-toolchain.tar.gz gs://syzkaller/
# gsutil acl ch -g all:R gs://syzkaller/GOOS-toolchain.tar.gz
#
# NetBSD toolchain can be re-built with:
# ./build.sh -j72 -m amd64 -U -T ../tools tools
# ./build.sh -j72 -m amd64 -U -T ../tools -D ../dest distribution
#
# To build root image run:
#	docker run -it --rm --privileged --device /dev/loop0 gcr.io/syzkaller/env
#	mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc
#	create-image.sh -a s390x -d buster

RUN curl https://storage.googleapis.com/syzkaller/fuchsia-toolchain.tar.gz | tar -C /syzkaller -xz
RUN curl https://storage.googleapis.com/syzkaller/netbsd-toolchain.tar.gz | tar -C /syzkaller -xz

# Now build the actual syz-env container.
FROM debian:bookworm

LABEL homepage="https://github.com/google/syzkaller"

RUN apt-get update --allow-releaseinfo-change
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
	sudo make nano unzip curl ca-certificates binutils g++ \
	g++-arm-linux-gnueabi g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu \
	g++-mips64el-linux-gnuabi64 g++-s390x-linux-gnu g++-riscv64-linux-gnu \
	libc6-dev-i386 libc6-dev-i386-amd64-cross lib32gcc-12-dev lib32stdc++-12-dev \
	python3 python-is-python3 git \
	# These are needed to build Linux kernel:
	flex bison bc libelf-dev libssl-dev \
	# qemu-user is required to run alien arch binaries in pkg/cover tests.
	qemu-user \
	# These are various fsck-like commands needed for prog/fsck:
	dosfstools e2fsprogs btrfs-progs util-linux f2fs-tools jfsutils \
	util-linux dosfstools ocfs2-tools reiserfsprogs xfsprogs erofs-utils \
	exfatprogs gfs2-utils \
	&& \
	apt-get -y autoremove && \
	apt-get clean autoclean && \
	rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Since go 1.21 the toolchain required by go.mod is automatically downloaded.
# There is no need to version up golang here after go.mod changes.
RUN curl https://dl.google.com/go/go1.22.7.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/go/bin:/gopath/bin:$PATH
ENV GOPATH /gopath
ENV GOMODCACHE /syzkaller/.cache/gomod

# Install clang.
RUN apt-get install -y -q gnupg software-properties-common apt-transport-https
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-15 main"
RUN apt-get update --allow-releaseinfo-change
RUN apt-get install -y -q --no-install-recommends clang-15 clang-format-15 clang-tidy-15
RUN apt-get install -y -q --no-install-recommends flatbuffers-compiler
RUN sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 100
RUN sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-15 100
RUN sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-15 100
RUN sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-15 100
RUN apt autoremove -y -q

# Install the Spanner emulator.
ARG SPANNER_EMULATOR_VERSION=1.5.28
RUN mkdir /spanner
RUN curl https://storage.googleapis.com/cloud-spanner-emulator/releases/${SPANNER_EMULATOR_VERSION}/cloud-spanner-emulator_linux_amd64-${SPANNER_EMULATOR_VERSION}.tar.gz | tar -C /spanner -xz
RUN chmod u+x /spanner/gateway_main /spanner/emulator_main
ENV SPANNER_EMULATOR_BIN=/spanner/gateway_main

RUN dpkg --add-architecture i386 && \
	apt-get update --allow-releaseinfo-change && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
	# required to build root images.
	debootstrap ssh-tools qemu-user-static && \
	apt-get -y autoremove && \
	apt-get clean autoclean && \
	rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Install Python 2.7.
COPY --from=python2-builder /python2/ /usr/local/
RUN ln -s /usr/local/bin/python2.7 /usr/bin/python2

# Copy the /syzkaller folder and set the toolchain environment variables.
COPY --from=syzkaller-folder /syzkaller/ /syzkaller/
RUN chmod 0777 /syzkaller
ENV SOURCEDIR_FUCHSIA /syzkaller/fuchsia
ENV SOURCEDIR_NETBSD /syzkaller/netbsd

# Install node to pass act jobs (https://github.com/nektos/act)
RUN apt-get install -y -q nodejs

# Install gcloud sdk for dashboard/app tests.
# The newest version (as of 07/10/23) is 437, however, it seems to expect to be run with python3
# (but still requires python2). But Go's aetest package still runs dev_appserver.py with python2.7.
# So let's use an older, but working sdk.
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-400.0.0-linux-x86_64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/google-cloud-sdk/bin:$PATH
RUN gcloud components install --quiet app-engine-python app-engine-go app-engine-python-extras cloud-datastore-emulator
RUN chmod 0777 /usr/local/google-cloud-sdk

# The default Docker prompt is too ugly and takes the whole line:
# I have no name!@0f3331d2fb54:~/gopath/src/github.com/google/syzkaller$
RUN echo "export PS1='syz-env🈴 '" > /syzkaller/.bashrc
ENV SYZ_ENV yes

ENTRYPOINT ["bash"]
