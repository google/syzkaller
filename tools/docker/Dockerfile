# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# See /tools/docker/README.md for details.

ARG CLANG_VERSION=22


# ==========================================
# Shared Builders
# ==========================================

# Stage: Build custom git (used by env)
FROM debian:trixie AS git-builder
RUN apt-get update && apt-get install -y -q --no-install-recommends \
    make gcc libc6-dev libssl-dev libcurl4-openssl-dev libexpat1-dev gettext zlib1g-dev curl ca-certificates autoconf \
    && rm -rf /var/lib/apt/lists/*
RUN curl -L https://github.com/git/git/archive/refs/tags/v2.54.0-rc2.tar.gz | tar -xz
RUN cd git-2.54.0-rc2 && \
    make configure && \
    ./configure --prefix=/opt/git && \
    make -j$(nproc) && \
    make install

# Stage: Pre-create /syzkaller and download Fuchsia/NetBSD toolchains (used by env-arch)
FROM debian:trixie AS toolchain-builder
WORKDIR /syzkaller
RUN apt-get update && apt-get install -y -q --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /syzkaller/gopath/src/github.com/google/syzkaller && \
	mkdir -p /syzkaller/.cache/gomod && \
	chmod -R 0777 /syzkaller
RUN curl https://storage.googleapis.com/syzkaller/fuchsia-toolchain.tar.gz | tar -xz
RUN curl https://storage.googleapis.com/syzkaller/netbsd-toolchain.tar.gz | tar -xz

# Stage: Build bindgen using temporary Rust installation (used by env-base)
FROM debian:trixie AS bindgen-builder
ARG CLANG_VERSION
RUN apt-get update && apt-get install -y -q --no-install-recommends \
    curl ca-certificates gnupg apt-transport-https gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | tee /usr/share/keyrings/llvm-snapshot.gpg && \
    echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/llvm-snapshot.gpg trusted=yes] http://apt.llvm.org/trixie/ llvm-toolchain-trixie-${CLANG_VERSION} main" | tee /etc/apt/sources.list.d/llvm-${CLANG_VERSION}.list && \
    apt-get update && \
    apt-get install -y -q --no-install-recommends clang-${CLANG_VERSION} libclang-${CLANG_VERSION}-dev llvm-${CLANG_VERSION}-dev && \
    rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.91.1
ENV LIBCLANG_PATH=/usr/lib/llvm-${CLANG_VERSION}/lib

RUN cargo install bindgen-cli --version 0.71.1

# Stage: Build the latest strace (used by syzbot)
FROM debian:trixie AS strace-builder
RUN apt-get update && apt-get install -y -q --no-install-recommends \
    make gcc libc6-dev git ca-certificates autoconf automake libtool \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v7.0 https://github.com/strace/strace.git /tmp/strace && \
    cd /tmp/strace && \
    ./bootstrap && \
    ./configure --enable-mpers=no LDFLAGS='-static -pthread' && \
    make -j$(nproc) && \
    mkdir -p /opt/bin && cp src/strace /opt/bin/strace


# ==========================================
# Target: env-base
# ==========================================
FROM debian:trixie AS env-base
LABEL homepage="https://github.com/google/syzkaller"
ARG CLANG_VERSION

# Install Python, core build tools, Clang, flatc, and dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    python3 python-is-python3 python3-legacy-cgi \
    make gcc libc6-dev nano unzip curl ca-certificates binutils flex bison bc libelf-dev libssl-dev \
    libcurl3t64-gnutls libexpat1 libpcre2-8-0 zlib1g perl liberror-perl \
    gnupg apt-transport-https && \
    # Add LLVM repo
    curl https://apt.llvm.org/llvm-snapshot.gpg.key | tee /usr/share/keyrings/llvm-snapshot.gpg && \
    echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/llvm-snapshot.gpg trusted=yes] http://apt.llvm.org/trixie/ llvm-toolchain-trixie-${CLANG_VERSION} main" | tee /etc/apt/sources.list.d/llvm-${CLANG_VERSION}.list && \
    apt-get update && \
    # Install Clang and flatbuffers
    apt-get install -y -q --no-install-recommends \
    clang-${CLANG_VERSION} clang-format-${CLANG_VERSION} clang-tidy-${CLANG_VERSION} lld-${CLANG_VERSION} llvm-${CLANG_VERSION}-dev libclang-cpp${CLANG_VERSION}-dev libclang-${CLANG_VERSION}-dev \
    flatbuffers-compiler && \
    # Set alternatives
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/lld-${CLANG_VERSION} 100 && \
    # Cleanup
    apt-get -y autoremove && \
    apt-get clean autoclean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Copy custom git
COPY --from=git-builder /opt/git /opt/git
RUN mkdir -p /opt/git/etc
ENV PATH /opt/git/bin:$PATH

# Copy bindgen
COPY --from=bindgen-builder /usr/local/cargo/bin/bindgen /usr/local/bin/bindgen
ENV LIBCLANG_PATH=/usr/lib/llvm-${CLANG_VERSION}/lib

# Install Go
RUN curl https://dl.google.com/go/go1.26.0.linux-$(dpkg --print-architecture).tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/go/bin:/gopath/bin:$PATH
ENV GOPATH /gopath
ENV GOMODCACHE /syzkaller/.cache/gomod

# Setup syzkaller dir structure
RUN mkdir -p /syzkaller/gopath/src/github.com/google/syzkaller && \
	mkdir -p /syzkaller/.cache/gomod && \
	chmod -R 0777 /syzkaller

RUN echo "export PS1='syz-env🈴 '" > /syzkaller/.bashrc
ENV SYZ_ENV yes
ENTRYPOINT ["bash"]


# ==========================================
# Intermediate: env-shared-libs (base + cross-compilers + FS tools + qemu-user)
# ==========================================
FROM env-base AS env-shared-libs

# Install cross-compilers and FS tools
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    g++ \
    g++-arm-linux-gnueabi g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu \
    g++-mips64el-linux-gnuabi64 g++-s390x-linux-gnu g++-riscv64-linux-gnu && \
    # Install architecture-specific packages (only for amd64)
    if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
        libc6-dev-i386 libc6-dev-i386-amd64-cross lib32gcc-14-dev lib32stdc++-14-dev; \
    fi && \
    # Install filesystem tools and qemu-user
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    qemu-user \
    dosfstools e2fsprogs btrfs-progs util-linux f2fs-tools jfsutils \
    ocfs2-tools reiserfsprogs xfsprogs erofs-utils \
    exfatprogs gfs2-utils && \
    # Cleanup
    apt-get -y autoremove && \
    apt-get clean autoclean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*


# ==========================================
# Target: env-arch (shared-libs + Fuchsia/NetBSD toolchains)
# ==========================================
FROM env-shared-libs AS env-arch

# Copy toolchains
COPY --from=toolchain-builder /syzkaller/ /syzkaller/
ENV SOURCEDIR_FUCHSIA /syzkaller/fuchsia
ENV SOURCEDIR_NETBSD /syzkaller/netbsd

# Install debootstrap, ssh-tools, qemu-user-static
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    debootstrap ssh-tools qemu-user-static && \
    # Cleanup
    apt-get -y autoremove && \
    apt-get clean autoclean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*


# ==========================================
# Target: env-dashboard
# ==========================================
FROM env-base AS env-dashboard

# Install Spanner emulator
ARG SPANNER_EMULATOR_VERSION=1.5.51
RUN mkdir /spanner && \
    curl https://storage.googleapis.com/cloud-spanner-emulator/releases/${SPANNER_EMULATOR_VERSION}/cloud-spanner-emulator_linux_amd64-${SPANNER_EMULATOR_VERSION}.tar.gz | tar -C /spanner -xz && \
    chmod u+x /spanner/gateway_main /spanner/emulator_main
ENV SPANNER_EMULATOR_BIN=/spanner/gateway_main

# Install gcloud sdk
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-560.0.0-linux-x86_64.tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/google-cloud-sdk/bin:$PATH
RUN gcloud components install --quiet app-engine-python app-engine-go app-engine-python-extras cloud-datastore-emulator && \
    chmod 0777 /usr/local/google-cloud-sdk && chmod -R 0777 /usr/local/google-cloud-sdk/platform/google_appengine


# ==========================================
# Target: env-full (Default Developer Image)
# ==========================================
FROM env-arch AS env-full

# Copy Spanner emulator and GCloud SDK from dashboard stage
COPY --from=env-dashboard /spanner /spanner
ENV SPANNER_EMULATOR_BIN=/spanner/gateway_main

COPY --from=env-dashboard /usr/local/google-cloud-sdk /usr/local/google-cloud-sdk
ENV PATH /usr/local/google-cloud-sdk/bin:$PATH

# Install Nodejs (needed for act)
RUN apt-get update && apt-get install -y -q nodejs && rm -rf /var/lib/apt/lists/*

# Copy Rust toolchain from bindgen-builder
COPY --from=bindgen-builder /usr/local/rustup /usr/local/rustup
COPY --from=bindgen-builder /usr/local/cargo /usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN rustup component add rust-src

# Install kernel build rust dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends libdw-dev libelf-dev && \
    rm -rf /var/lib/apt/lists/*


# ==========================================
# Target: syzbot
# ==========================================
FROM env-shared-libs AS syzbot
ARG CLANG_VERSION

# Install syzbot specific packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    # Build essentials & utilities additional to base
    ccache sudo procps psmisc vim bzip2 dh-autoreconf fdisk rsync libarchive-tools \
    # Kernel build tools
    gawk dwarves cpio texinfo texi2html lzop lbzip2 libncurses-dev libmpc-dev \
    # gVisor build dependencies
    crossbuild-essential-amd64 crossbuild-essential-arm64 libbpf-dev binutils-gold \
    # QEMU system emulators
    qemu-utils qemu-system-misc qemu-system-x86 qemu-system-arm qemu-system-aarch64 && \
    # QEMU system emulators for other arches (only on x86_64)
    if [ "$(uname -m)" = "x86_64" ]; then \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
        qemu-system-s390x qemu-system-mips qemu-system-ppc; \
    fi && \
    # Cleanup
    apt-get -y autoremove && \
    apt-get clean autoclean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Install Clang 15 (for kernel bisections)
RUN echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/llvm-snapshot.gpg trusted=yes] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-15 main" | tee /etc/apt/sources.list.d/llvm-bookworm-15.list && \
    apt-get update && \
    apt-get install -y -q --no-install-recommends -t llvm-toolchain-bookworm-15 clang-15 && \
    apt-get install -y --no-install-recommends libdwarf-dev libdw-dev libelf-dev && \
    rm -rf /var/lib/apt/lists/*

# Set up update-alternatives for LLVM tools in syzbot
RUN update-alternatives --install /usr/bin/llvm-nm llvm-nm /usr/bin/llvm-nm-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-addr2line llvm-addr2line /usr/bin/llvm-addr2line-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-readelf llvm-readelf /usr/bin/llvm-readelf-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-${CLANG_VERSION} 100 && \
    update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-${CLANG_VERSION} 100

# Install Bazelisk
RUN curl -s https://api.github.com/repos/bazelbuild/bazelisk/releases/latest \
        | sed -n '/browser_download_url/s/[^:]*:[^"]*\("[^"]*"\).*/url = \1/p' \
        | grep bazelisk-linux-$(uname -m | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) \
        | curl -L -o /usr/local/bin/bazel -K - \
        && chmod +x /usr/local/bin/bazel

# Copy custom strace
COPY --from=strace-builder /opt/bin/strace /opt/bin/strace

# Copy Rust toolchain from bindgen-builder
COPY --from=bindgen-builder /usr/local/rustup /usr/local/rustup
COPY --from=bindgen-builder /usr/local/cargo /usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN rustup component add rust-src

# Copy GCloud SDK from env-dashboard
COPY --from=env-dashboard /usr/local/google-cloud-sdk /usr/local/google-cloud-sdk
ENV PATH /usr/local/google-cloud-sdk/bin:$PATH
RUN git config --system credential.'https://*.*.sourcemanager.dev'.helper gcloud.sh

# Not really GRTE, but it's enough to run some scripts that hardcode the path.
RUN mkdir -p /usr/grte/v5/bin && ln -s /usr/bin/python3 /usr/grte/v5/bin/python2.7

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller
RUN echo "export PS1='\n\W🤖 '" >> /root/.bashrc

# Copy run-syz-command.sh (expects build context to have syzbot/run-syz-command.sh)
COPY syzbot/run-syz-command.sh /run-syz-command.sh
RUN chmod +x /run-syz-command.sh
