# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM golang:1.24-alpine AS triage-action-builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Build the tool.
COPY --exclude=.git . .
RUN go build -o /build/triage-action-bin /build/syz-cluster/workflow/triage

FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y git

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd -u 10000 --create-home syzkaller
# Prevent "fatal: detected dubious ownership in repository" errors.
RUN git config --system --add safe.directory /workdir
RUN git config --system --add safe.directory /kernel-repo

COPY --from=triage-action-builder /build/triage-action-bin /bin/triage-action

ENTRYPOINT ["/bin/triage-action"]
