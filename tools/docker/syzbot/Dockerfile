# Copyright 2021 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# See /tools/docker/README.md for details.

FROM debian:trixie

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
	# Build essentials:
	gcc g++ binutils make ccache \
	# Some common utilities:
	unzip curl sudo procps psmisc nano vim git bzip2 dh-autoreconf fdisk \
	# These are needed to build Linux kernel:
	flex bison bc gawk dwarves cpio texinfo texi2html lzop lbzip2 \
	zlib1g-dev libncurses-dev libmpc-dev libssl-dev \
	apt-transport-https curl gnupg python-is-python3 python3-legacy-cgi \
	# Needed for building Cuttlefish images.
	rsync libarchive-tools \
	# These are various fsck-like commands needed for prog/fsck:
	dosfstools e2fsprogs btrfs-progs util-linux f2fs-tools jfsutils \
	util-linux dosfstools ocfs2-tools reiserfsprogs xfsprogs erofs-utils \
	exfatprogs gfs2-utils \
	# Needed for buiding gVisor.
	crossbuild-essential-amd64 crossbuild-essential-arm64 libbpf-dev binutils-gold
RUN test "$(uname -m)" != x86_64 && exit 0 || \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
	  libc6-dev-i386 libc6-dev-i386-amd64-cross lib32gcc-14-dev lib32stdc++-14-dev \
	  # Cross-compilation:
	  g++-arm-linux-gnueabi g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu \
	  g++-mips64el-linux-gnuabi64 g++-s390x-linux-gnu g++-riscv64-linux-gnu

# Since go 1.21 the toolchain required by go.mod is automatically downloaded.
# There is no need to version up golang here after go.mod changes.
RUN curl https://dl.google.com/go/go1.24.4.linux-$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/').tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/go/bin:$PATH

# Install the latest clang
RUN apt-get install -y -q gnupg apt-transport-https
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | tee /usr/share/keyrings/llvm-snapshot.gpg
# It uses SHA-1 signatures which are deprecated since 2026, so we have to use trusted=yes.
RUN echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/llvm-snapshot.gpg trusted=yes] http://apt.llvm.org/trixie/ llvm-toolchain-trixie-21 main" | tee /etc/apt/sources.list.d/llvm-21.list
RUN apt-get update --allow-releaseinfo-change
RUN apt-get install -y -q --no-install-recommends llvm-21 clang-21 clang-format-21 clang-tidy-21 lld-21 llvm-21-dev libclang-cpp21-dev libclang-21-dev
RUN apt autoremove -y -q
RUN sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-21 100
RUN sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-21 100
RUN sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-21 100
RUN sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-21 100
RUN sudo update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/lld-21 100
RUN sudo update-alternatives --install /usr/bin/llvm-nm llvm-nm /usr/bin/llvm-nm-21 100
RUN sudo update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-21 100
RUN sudo update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-21 100
RUN sudo update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-21 100
RUN sudo update-alternatives --install /usr/bin/llvm-addr2line llvm-addr2line /usr/bin/llvm-addr2line-21 100
RUN sudo update-alternatives --install /usr/bin/llvm-readelf llvm-readelf /usr/bin/llvm-readelf-21 100
RUN sudo update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-21 100
RUN sudo update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-21 100

# Also install clang-15 to keep bisections alive.
RUN echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/llvm-snapshot.gpg trusted=yes] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-15 main" | sudo tee /etc/apt/sources.list.d/llvm-bookworm-15.list
RUN apt-get update --allow-releaseinfo-change
RUN apt-get install -y -q --no-install-recommends -t llvm-toolchain-bookworm-15 clang-15
RUN apt-get install libelf-dev libdwarf-dev

# Not really GRTE, but it's enough to run some scripts that hardcode the path.
RUN mkdir -p /usr/grte/v5/bin && ln -s /usr/bin/python3 /usr/grte/v5/bin/python2.7

# Install bazelisk
RUN curl -s https://api.github.com/repos/bazelbuild/bazelisk/releases/latest \
        | sed -n '/browser_download_url/s/[^:]*:[^"]*\("[^"]*"\).*/url = \1/p' \
        | grep bazelisk-linux-$(uname -m | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) \
        | curl -L -o /usr/local/bin/bazel -K - \
        && chmod +x /usr/local/bin/bazel

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
# This is required to run alien arch binaries in pkg/cover tests:
	qemu-user

# QEMU packages required to run x86/arm64 kernels - install them for both x86 and arm64.
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    qemu-utils qemu-system-misc qemu-system-x86 qemu-system-arm qemu-system-aarch64

# Install QEMU packages for other arches on x86 machines only.
RUN test "$(uname -m)" != x86_64 && exit 0 || \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    qemu-system-s390x qemu-system-mips qemu-system-ppc

# Rust toolchain for kernel builds.
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
ENV RUST_VERSION=1.91.1
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUST_VERSION
RUN rustup component add rust-src
RUN cargo install --locked bindgen-cli

RUN apt-get install -y --no-install-recommends libdw-dev libelf-dev

# Install gcloud https://cloud.google.com/sdk/docs/install#deb.
RUN apt-get install -y -q ca-certificates \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
RUN apt-get update && apt-get install -y google-cloud-cli
RUN git config --system credential.'https://*.*.sourcemanager.dev'.helper gcloud.sh

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller
RUN echo "export PS1='\n\W🤖 '" >> /root/.bashrc

COPY run-syz-command.sh /run-syz-command.sh
