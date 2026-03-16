# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

ARG IMAGE_PREFIX=local/
ARG IMAGE_TAG=latest
FROM ${IMAGE_PREFIX}syz-cluster-build:${IMAGE_TAG} AS builder

FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y git

COPY --from=builder /build/syz-cluster/bin/series-tracker /bin/series-tracker

ENTRYPOINT ["/bin/series-tracker"]
