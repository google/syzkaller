# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
FROM golang:1.24-alpine AS email-reporter-builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Build the tool.
COPY --exclude=.git . .
RUN go build -o /bin/email-reporter /build/syz-cluster/email-reporter

# Build the container.
FROM alpine:latest

RUN apk update && \
    apk add git

WORKDIR /app

COPY --from=email-reporter-builder /bin/email-reporter /bin/email-reporter

ENTRYPOINT ["/bin/email-reporter"]
