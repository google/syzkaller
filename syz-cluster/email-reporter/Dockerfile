# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
ARG IMAGE_PREFIX=local/
ARG IMAGE_TAG=latest
FROM ${IMAGE_PREFIX}syz-cluster-build:${IMAGE_TAG} AS builder

# Build the container.
FROM alpine:latest

RUN apk update && \
    apk add git

WORKDIR /app

COPY --from=builder /build/syz-cluster/bin/email-reporter /bin/email-reporter

ENTRYPOINT ["/bin/email-reporter"]
