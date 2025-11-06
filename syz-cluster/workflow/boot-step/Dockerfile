# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Build syzkaller.
FROM gcr.io/syzkaller/env as syzkaller-builder
WORKDIR /build
# First query the modules to facilitate caching.
COPY go.mod go.sum ./
RUN go mod download
COPY --exclude=syz-cluster . .
RUN make TARGETARCH=amd64

FROM golang:1.24-alpine AS boot-step-builder
WORKDIR /build

# Copy the code and the dependencies.
COPY go.mod go.sum ./
RUN go mod download
COPY pkg/ pkg/
COPY prog/ prog/
COPY vm/ vm/
COPY executor/ executor/
COPY dashboard/dashapi/ dashboard/dashapi/
# Copying from the builder to take the `make descriptions` result.
COPY --from=syzkaller-builder /build/sys/ sys/
COPY syz-cluster/workflow/boot-step/*.go syz-cluster/workflow/boot-step/
COPY syz-cluster/pkg/ syz-cluster/pkg/

RUN go build -o /bin/boot-step /build/syz-cluster/workflow/boot-step

FROM debian:bookworm

RUN apt-get update && \
    apt-get install -y qemu-system openssh-client

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller

COPY --from=syzkaller-builder /build/bin/ /syzkaller/bin/
COPY --from=boot-step-builder /bin/boot-step /bin/boot-step

ENTRYPOINT ["/bin/boot-step"]
