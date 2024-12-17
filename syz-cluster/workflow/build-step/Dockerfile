# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM golang:1.23-alpine AS build-step-builder

WORKDIR /build

# Copy the code and the dependencies.
COPY go.mod go.sum ./
RUN go mod download
COPY pkg/ pkg/
# TODO: get rid of the prog/ dependency?
COPY prog/ prog/
COPY vm/ vm/
COPY dashboard/dashapi/ dashboard/dashapi/
COPY sys/ sys/
COPY syz-cluster/workflow/build-step/*.go syz-cluster/workflow/build-step/
COPY syz-cluster/pkg/ syz-cluster/pkg/

RUN go build -o /build/build-step-bin /build/syz-cluster/workflow/build-step

FROM debian:bookworm

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller

# The prerequisites for building the kernel.
RUN apt-get update && \
    apt-get install -y git make binutils gcc g++ binutils make \
    flex bison bc gawk dwarves cpio texinfo texi2html lzop lbzip2 \
    zlib1g-dev libelf-dev libncurses-dev libmpc-dev libssl-dev \
    apt-transport-https curl gnupg python-is-python3

# TODO: it's duplicated from the syzbot's Docker container.

# The default clang-14 is too old, install the latest one.
RUN apt-get install -y -q gnupg software-properties-common apt-transport-https
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-15 main"
RUN apt-get update --allow-releaseinfo-change
RUN apt-get install -y -q --no-install-recommends llvm-15 clang-15 clang-format-15 clang-tidy-15 lld-15
RUN apt autoremove -y -q
RUN apt-get update && apt-get install -y sudo 
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
RUN sudo update-alternatives --install /usr/bin/llvm-readelf llvm-readelf /usr/bin/llvm-readelf-15 100
RUN sudo update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-15 100

# Download the base buildroot image.
RUN apt-get update && apt-get install -y wget
RUN mkdir -p /disk-images
RUN wget https://storage.googleapis.com/syzkaller/images/buildroot_amd64_2024.09.gz -O /disk-images/buildroot_amd64_2024.09.gz
RUN gzip -d /disk-images/buildroot_amd64_2024.09.gz

# Download some base kernel configs.

RUN mkdir -p /kernel-configs
RUN wget https://raw.githubusercontent.com/google/syzkaller/refs/heads/master/dashboard/config/linux/upstream-apparmor-kasan.config -O /kernel-configs/upstream-apparmor-kasan.config

COPY --from=build-step-builder /build/build-step-bin /bin/build-step

ENTRYPOINT ["/bin/series-tracker"]
