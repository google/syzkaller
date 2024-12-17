# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM golang:1.23-alpine AS series-tracker-builder

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
COPY syz-cluster/series-tracker/*.go syz-cluster/series-tracker/
COPY syz-cluster/pkg/ syz-cluster/pkg/

RUN go build -o /build/series-tracker-bin /build/syz-cluster/series-tracker

FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y git

COPY --from=series-tracker-builder /build/series-tracker-bin /bin/series-tracker

ENTRYPOINT ["/bin/series-tracker"]
