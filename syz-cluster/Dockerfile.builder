# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
FROM gcr.io/syzkaller/env AS builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/syzkaller/.cache/gomod go mod download

ARG REV
ARG GITREVDATE

# Build syzkaller.
COPY --exclude=.git --exclude=syz-cluster . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/syzkaller/.cache/gomod \
    make TARGETARCH=amd64 REV=$REV GITREVDATE=$GITREVDATE

# Build syz-cluster tools.
COPY syz-cluster ./syz-cluster
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/syzkaller/.cache/gomod \
    cd syz-cluster && \
    GO_FLAGS="$(make -s -C .. go-flags REV=$REV GITREVDATE=$GITREVDATE 2>/dev/null)" CGO_ENABLED=0 make -j all

# Final stage to retain only built binaries, keeping the image small.
FROM scratch
COPY --from=builder /build/bin/ /build/bin/
COPY --from=builder /build/syz-cluster/bin/ /build/syz-cluster/bin/
