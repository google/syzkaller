# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM gcr.io/syzkaller/env AS build-step-builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY --exclude=syz-cluster . .
COPY syz-cluster/workflow/build-step/*.go syz-cluster/workflow/build-step/
COPY syz-cluster/pkg/ syz-cluster/pkg/
RUN go build -o /build/build-step-bin /build/syz-cluster/workflow/build-step

# Build on the latest syzbot image.
FROM gcr.io/syzkaller/syzbot:latest

# Download the base buildroot image.
RUN mkdir -p /disk-images
ADD https://storage.googleapis.com/syzkaller/images/buildroot_amd64_2024.09.gz /disk-images/buildroot_amd64_2024.09.gz
RUN gzip -d /disk-images/buildroot_amd64_2024.09.gz

# Download base kernel configs.
RUN mkdir -p /kernel-configs
ADD https://raw.githubusercontent.com/google/syzkaller/refs/heads/master/dashboard/config/linux/upstream-apparmor-kasan.config /kernel-configs/upstream-apparmor-kasan.config

COPY --from=build-step-builder /build/build-step-bin /bin/build-step

ENTRYPOINT ["/bin/series-tracker"]
