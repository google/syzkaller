# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# See /tools/docker/README.md for details.

# Construct a /syzkaller folder.
FROM debian:trixie AS syzkaller-folder
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

# gcloud storage mv gs://syzkaller/GOOS-toolchain.tar.gz gs://syzkaller/GOOS-toolchain.old.tar.gz

# gcloud storage cp GOOS-toolchain.tar.gz gs://syzkaller/

# gcloud storage objects update gs://syzkaller/GOOS-toolchain.tar.gz --add-acl-grant=entity=allUsers,role=READER
#
# NetBSD toolchain can be re-built with:
# ./build.sh -j72 -m amd64 -U -T ../tools tools
# ./build.sh -j72 -m amd64 -U -T ../tools -D ../dest distribution
#
# To build root image run:
#	docker run -it --rm --privileged --device /dev/loop0 gcr.io/syzkaller/env
#	mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc
#	create-image.sh -a <ARCH> -d <DEBIAN RELEASE>

RUN curl https://storage.googleapis.com/syzkaller/fuchsia-toolchain.tar.gz | tar -C /syzkaller -xz
RUN curl https://storage.googleapis.com/syzkaller/netbsd-toolchain.tar.gz | tar -C /syzkaller -xz

# Build the latest git.
FROM debian:trixie AS git-builder
RUN apt-get update && apt-get install -y -q --no-install-recommends \
    make gcc libc6-dev libssl-dev libcurl4-openssl-dev libexpat1-dev gettext zlib1g-dev curl ca-certificates autoconf
RUN curl -L https://github.com/git/git/archive/refs/tags/v2.54.0-rc2.tar.gz | tar -xz
RUN cd git-2.54.0-rc2 && \
    make configure && \
    ./configure --prefix=/opt/git && \
    make -j$(nproc) && \
    make install

# Now build the actual syz-env container.
FROM debian:trixie

LABEL homepage="https://github.com/google/syzkaller"

# Install Python and core build tools.
RUN apt-get update --allow-releaseinfo-change && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    python3 python-is-python3 python3-legacy-cgi \
    make nano unzip curl ca-certificates binutils flex bison bc libelf-dev libssl-dev \
    # Explicitly install git runtime dependencies since we build it from source.
    libcurl3t64-gnutls libexpat1 libpcre2-8-0 zlib1g perl liberror-perl

# Copy the custom git build and prioritize it in PATH.
COPY --from=git-builder /opt/git /opt/git

# Install heavy cross-compilers.
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    g++ \
    g++-arm-linux-gnueabi g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu \
    g++-mips64el-linux-gnuabi64 g++-s390x-linux-gnu g++-riscv64-linux-gnu

# Install architecture-specific packages (only for amd64).
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
        libc6-dev-i386 libc6-dev-i386-amd64-cross lib32gcc-14-dev lib32stdc++-14-dev; \
    fi

# Install filesystem tools and qemu-user, clean up.
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    qemu-user \
    dosfstools e2fsprogs btrfs-progs util-linux f2fs-tools jfsutils \
    ocfs2-tools reiserfsprogs xfsprogs erofs-utils \
    exfatprogs gfs2-utils && \
    apt-get -y autoremove && \
    apt-get clean autoclean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Since go 1.21 the toolchain required by go.mod is automatically downloaded.
# There is no need to version up golang here after go.mod changes.
RUN curl https://dl.google.com/go/go1.26.0.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH /opt/git/bin:/usr/local/go/bin:/gopath/bin:$PATH
ENV GOPATH /gopath
ENV GOMODCACHE /syzkaller/.cache/gomod

# Install clang.
RUN apt-get install -y -q gnupg apt-transport-https
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | tee /usr/share/keyrings/llvm-snapshot.gpg
# It uses SHA-1 signatures which are deprecated since 2026, so we have to use trusted=yes.
RUN echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/llvm-snapshot.gpg trusted=yes] http://apt.llvm.org/trixie/ llvm-toolchain-trixie-21 main" | tee /etc/apt/sources.list.d/llvm-21.list
RUN apt-get update --allow-releaseinfo-change
RUN apt-get install -y -q --no-install-recommends clang-21 clang-format-21 clang-tidy-21 lld-21 llvm-21-dev libclang-cpp21-dev libclang-21-dev
RUN apt-get install -y -q --no-install-recommends flatbuffers-compiler
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-21 100
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-21 100
RUN update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-21 100
RUN update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-21 100
RUN update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/lld-21 100
RUN apt autoremove -y -q

# Install the Spanner emulator.
ARG SPANNER_EMULATOR_VERSION=1.5.51
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

# Copy the /syzkaller folder and set the toolchain environment variables.
COPY --from=syzkaller-folder /syzkaller/ /syzkaller/
RUN chmod 0777 /syzkaller
ENV SOURCEDIR_FUCHSIA /syzkaller/fuchsia
ENV SOURCEDIR_NETBSD /syzkaller/netbsd

# Rust toolchain for kernel builds.
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
ENV RUST_VERSION=1.91.1
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUST_VERSION
RUN rustup component add rust-src
RUN apt-get install -y bindgen

# Use the latest libdw-dev release, otherwise we get compilation error when CONFIG_RUST=y.
RUN apt-get install -y --no-install-recommends libdw-dev libelf-dev

# Install node to pass act jobs (https://github.com/nektos/act)
RUN apt-get install -y -q nodejs

# Install gcloud sdk for dashboard/app tests.
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-560.0.0-linux-x86_64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/google-cloud-sdk/bin:$PATH
RUN gcloud components install --quiet app-engine-python app-engine-go app-engine-python-extras cloud-datastore-emulator
# chmod 0777 is used because syz-env runs as the host user (dynamic UID/GID) at runtime.
# We recursive-chmod only platform/google_appengine to avoid traversing the entire SDK,
# which has millions of files and would otherwise stall the build.
RUN chmod 0777 /usr/local/google-cloud-sdk && chmod -R 0777 /usr/local/google-cloud-sdk/platform/google_appengine

# The default Docker prompt is too ugly and takes the whole line:
# I have no name!@0f3331d2fb54:~/gopath/src/github.com/google/syzkaller$
RUN echo "export PS1='syz-env🈴 '" > /syzkaller/.bashrc
ENV SYZ_ENV yes

ENTRYPOINT ["bash"]
