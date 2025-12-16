# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM golang:1.24-alpine AS triage-step-builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Build the tool.
COPY pkg/ pkg/
# TODO: get rid of this dependency.
COPY prog/ prog/
COPY dashboard/dashapi/ dashboard/dashapi/
COPY sys/targets/ sys/targets/ 
COPY syz-cluster/workflow/triage-step/*.go syz-cluster/workflow/triage-step/
COPY syz-cluster/pkg/ syz-cluster/pkg/

RUN go build -o /build/triage-step-bin /build/syz-cluster/workflow/triage-step

FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y git

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd -u 10000 --create-home syzkaller
# Prevent "fatal: detected dubious ownership in repository" errors.
RUN git config --system --add safe.directory /workdir
RUN git config --system --add safe.directory /kernel-repo

COPY --from=triage-step-builder /build/triage-step-bin /bin/triage-step

ENTRYPOINT ["/bin/series-tracker"]
