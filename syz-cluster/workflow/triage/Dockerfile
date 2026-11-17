# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

ARG IMAGE_PREFIX=local/
ARG IMAGE_TAG=latest
FROM ${IMAGE_PREFIX}syz-cluster-build:${IMAGE_TAG} AS builder

FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y git bubblewrap socat

# pkg/osutil runs commands as the syzkaller user in a bubblewrap sandbox,
# socat is needed to proxy git:// connections out of it.
RUN useradd -u 10000 --create-home syzkaller
# Prevent "fatal: detected dubious ownership in repository" errors.
RUN git config --system --add safe.directory /workdir
RUN git config --system --add safe.directory /kernel-repo

COPY --from=builder /build/syz-cluster/bin/triage-action /bin/triage-action

ENTRYPOINT ["/bin/triage-action"]
