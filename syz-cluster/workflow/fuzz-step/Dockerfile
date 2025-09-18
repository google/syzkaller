# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM gcr.io/syzkaller/env AS fuzz-step-builder
WORKDIR /build

# Copy the code and the dependencies.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make TARGETARCH=amd64
COPY syz-cluster/ syz-cluster/
RUN GO_FLAGS=$(make go-flags 2>/dev/null) && go build "$GO_FLAGS" -o /bin/fuzz-step /build/syz-cluster/workflow/fuzz-step

FROM debian:bookworm

RUN apt-get update && \
    apt-get install -y qemu-system openssh-client curl cpp gcc

# Install clang tools.
RUN apt-get install -y -q gnupg software-properties-common apt-transport-https
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-20 main" | tee /etc/apt/sources.list.d/llvm-20.list
RUN apt-get update --allow-releaseinfo-change
RUN apt-get install -y -q --no-install-recommends llvm-20 clang-20 clang-format-20
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-20 100
RUN update-alternatives --install /usr/bin/llvm-addr2line llvm-addr2line /usr/bin/llvm-addr2line-20 100
RUN update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-20 100

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller

COPY --from=fuzz-step-builder /build/bin/ /syzkaller/bin/
COPY --from=fuzz-step-builder /bin/fuzz-step /bin/fuzz-step

ENTRYPOINT ["/bin/fuzz-step"]
