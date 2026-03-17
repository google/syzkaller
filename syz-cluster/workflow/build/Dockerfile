# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

ARG SMOKE_TEST=0
ARG IMAGE_PREFIX=local/
ARG IMAGE_TAG=latest
FROM ${IMAGE_PREFIX}syz-cluster-build:${IMAGE_TAG} AS builder

# Regular setup (SMOKE_TEST=0)
# Build on the latest syzbot image.
FROM gcr.io/syzkaller/syzbot:latest AS setup-0

# Download the base buildroot image.
RUN mkdir -p /disk-images
ADD https://storage.googleapis.com/syzkaller/images/buildroot_amd64_2024.09.gz /disk-images/buildroot_amd64_2024.09.gz
RUN gzip -d /disk-images/buildroot_amd64_2024.09.gz
RUN chmod 644 /disk-images/*

# Download base kernel configs.
RUN mkdir -p /kernel-configs
ADD https://raw.githubusercontent.com/google/syzkaller/refs/heads/master/dashboard/config/linux/upstream-apparmor-kasan.config /kernel-configs/upstream-apparmor-kasan.config
ADD https://raw.githubusercontent.com/google/syzkaller/refs/heads/master/dashboard/config/linux/upstream-kmsan.config /kernel-configs/upstream-kmsan.config
RUN chmod 644 /kernel-configs/*

# Prevent "fatal: detected dubious ownership in repository" errors.
RUN git config --system --add safe.directory /workdir
RUN git config --system --add safe.directory /kernel-repo

# Smoke test setup (SMOKE_TEST=1)
FROM debian:bookworm-slim AS setup-1
# Skip heavy syzbot image and downloads for smoke test
RUN echo "Smoke test mode: skipping syzbot base and disk images"

FROM setup-${SMOKE_TEST} AS final

COPY --from=builder /build/syz-cluster/bin/build-action /bin/build-action

ENTRYPOINT ["/bin/build-action"]
