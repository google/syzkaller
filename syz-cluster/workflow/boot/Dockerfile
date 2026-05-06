# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

ARG SMOKE_TEST=0
ARG IMAGE_PREFIX=local/
ARG IMAGE_TAG=latest
FROM ${IMAGE_PREFIX}syz-cluster-build:${IMAGE_TAG} AS builder

# Regular setup (SMOKE_TEST=0)
FROM debian:bookworm-slim AS setup-0
RUN apt-get update && \
    apt-get install -y qemu-system openssh-client

# Smoke test setup (SMOKE_TEST=1)
FROM debian:bookworm-slim AS setup-1
# Skip heavy installs for smoke test
RUN echo "Smoke test mode: skipping dependencies"

FROM setup-${SMOKE_TEST} AS final

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller

COPY --from=builder /build/bin/ /syzkaller/bin/
COPY --from=builder /build/syz-cluster/bin/boot-action /bin/boot-action

ENTRYPOINT ["/bin/boot-action"]
