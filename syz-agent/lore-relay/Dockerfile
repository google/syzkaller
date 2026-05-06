# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM gcr.io/syzkaller/env AS lore-relay-builder
WORKDIR /syzkaller

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN make lore-relay

FROM alpine:latest

RUN apk update && \
    apk add git

WORKDIR /app
COPY --from=lore-relay-builder /syzkaller/bin/syz-lore-relay /app/syz-lore-relay
ENTRYPOINT ["/app/syz-lore-relay"]
