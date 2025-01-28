# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM gcr.io/syzkaller/env AS fuzz-step-builder
WORKDIR /build

# Copy the code and the dependencies.
COPY go.mod go.sum ./
RUN go mod download
COPY --exclude=syz-cluster . .
RUN make TARGETARCH=amd64
COPY syz-cluster/ syz-cluster/
RUN GO_FLAGS=$(make go-flags 2>/dev/null) && go build "$GO_FLAGS" -o /bin/fuzz-step /build/syz-cluster/workflow/fuzz-step

FROM debian:bookworm

RUN apt-get update && \
    apt-get install -y qemu-system openssh-client

# pkg/osutil uses syzkaller user for sandboxing.
RUN useradd --create-home syzkaller

COPY --from=fuzz-step-builder /build/bin/ /syzkaller/bin/
COPY --from=fuzz-step-builder /bin/fuzz-step /bin/fuzz-step
COPY syz-cluster/workflow/configs/ /configs/

ENTRYPOINT ["/bin/fuzz-step"]
