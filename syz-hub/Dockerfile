# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM gcr.io/syzkaller/env AS syz-hub-builder
WORKDIR /syzkaller

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG REV
ARG GITREVDATE
ENV REV=${REV}
ENV GITREVDATE=${GITREVDATE}

RUN CGO_ENABLED=0 make hub

FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=syz-hub-builder /syzkaller/bin/syz-hub /app/syz-hub
ENTRYPOINT ["/app/syz-hub"]
