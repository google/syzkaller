# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM golang:1.23-alpine AS submit-test-builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Build the tool.
COPY syz-cluster/workflow/submit-test/*.go syz-cluster/workflow/submit-test/
COPY syz-cluster/pkg/ syz-cluster/pkg/

RUN go build -o /build/submit-test-bin /build/syz-cluster/workflow/submit-test

FROM ubuntu:latest

COPY --from=submit-test-builder /build/submit-test-bin /bin/submit-test

ENTRYPOINT ["/bin/submit-test"]
