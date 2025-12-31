# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Build the tool.
COPY --exclude=.git . .
RUN go build -o /bin/db-mgmt /build/syz-cluster/tools/db-mgmt

# Create the actual container.
FROM alpine:latest
WORKDIR /app

COPY --from=builder /bin/db-mgmt /bin/db-mgmt

ENTRYPOINT ["/bin/db-mgmt"]
