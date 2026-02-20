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

FROM golang:1.24-alpine AS boot-action-builder
WORKDIR /build

# Copy the code and the dependencies.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Copying from the builder to take the `make descriptions` result.
COPY --from=syzkaller-builder /build/sys/ sys/

RUN go build -o /bin/boot-action /build/syz-cluster/workflow/boot

FROM debian:bookworm

RUN apt-get update && \
    apt-get install -y qemu-system openssh-client

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller

COPY --from=syzkaller-builder /build/bin/ /syzkaller/bin/
COPY --from=boot-action-builder /bin/boot-action /bin/boot-action

ENTRYPOINT ["/bin/boot-action"]
