# Copyright 2021 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# See /tools/docker/README.md for details.

FROM debian:bookworm

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
	# Build essentials:
	gcc g++ binutils make ccache \
	# Some common utilities:
	unzip curl sudo procps psmisc nano vim git bzip2 dh-autoreconf software-properties-common \
	# These are needed to build Linux kernel:
	flex bison bc gawk dwarves cpio texinfo texi2html lzop lbzip2 \
	zlib1g-dev libelf-dev libncurses-dev libmpc-dev libssl-dev \
	apt-transport-https curl gnupg python-is-python3 \
	# Needed for building Cuttlefish images.
	rsync libarchive-tools \
	# Needed for buiding gVisor.
	crossbuild-essential-amd64 crossbuild-essential-arm64 libbpf-dev
RUN test "$(uname -m)" != x86_64 && exit 0 || \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
	  libc6-dev-i386 libc6-dev-i386-amd64-cross lib32gcc-12-dev lib32stdc++-12-dev \
	  # Cross-compilation:
	  g++-arm-linux-gnueabi g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu \
	  g++-mips64el-linux-gnuabi64 g++-s390x-linux-gnu g++-riscv64-linux-gnu

RUN curl https://dl.google.com/go/go1.21.4.linux-$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/').tar.gz | tar -C /usr/local -xz
ENV PATH /usr/local/go/bin:$PATH

# The default clang-14 is too old, install the latest one.
RUN apt-get install -y -q gnupg software-properties-common apt-transport-https
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-15 main"
RUN apt-get update --allow-releaseinfo-change
RUN apt-get install -y -q --no-install-recommends llvm-15 clang-15 clang-format-15 clang-tidy-15 lld-15
RUN apt autoremove -y -q
RUN sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 100
RUN sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-15 100
RUN sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-15 100
RUN sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-15 100
RUN sudo update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/lld-15 100
RUN sudo update-alternatives --install /usr/bin/llvm-nm llvm-nm /usr/bin/llvm-nm-15 100
RUN sudo update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-15 100
RUN sudo update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-15 100
RUN sudo update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-15 100
RUN sudo update-alternatives --install /usr/bin/llvm-addr2line llvm-addr2line /usr/bin/llvm-addr2line-15 100

# Not really GRTE, but it's enough to run some scripts that hardcode the path.
RUN mkdir -p /usr/grte/v5/bin && ln -s /usr/bin/python3 /usr/grte/v5/bin/python2.7

# Install bazel
# Download the official bazel binary. The APT repository isn't used because there is not packages for arm64.
RUN sh -c 'curl -o /usr/local/bin/bazel https://releases.bazel.build/7.1.2/release/bazel-7.1.2-linux-$(uname -m | sed s/aarch64/arm64/) && chmod ugo+x /usr/local/bin/bazel'

# Install qemu from the backports.
# The currently stable version (7.4) cannot properly run arm64-MTE kernels.
RUN add-apt-repository "deb http://deb.debian.org/debian bookworm-backports main"
RUN DEBIAN_FRONTEND=noninteractive apt-get install -t bookworm-backports -y -q \
# This is required to run alien arch binaries in pkg/cover tests:
	qemu-user
RUN test "$(uname -m)" != x86_64 && exit 0 || \
    DEBIAN_FRONTEND=noninteractive apt-get install -t bookworm-backports -y -q \
    # These are required to run foreign arch kernels:
    qemu-utils qemu-system-misc qemu-system-x86 qemu-system-arm qemu-system-aarch64  \
    qemu-system-s390x qemu-system-mips qemu-system-ppc

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller
RUN echo "export PS1='\n\W🤖 '" >> /root/.bashrc

COPY run-syz-command.sh /run-syz-command.sh
