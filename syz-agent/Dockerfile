# syntax=docker.io/docker/dockerfile:1.7-labs
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FROM gcr.io/syzkaller/env AS syz-agent-builder
WORKDIR /syzkaller

# Prepare the dependencies.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG REV
ARG GITREVDATE
ENV REV=${REV}
ENV GITREVDATE=${GITREVDATE}

RUN make target OS=linux
RUN make agent

FROM gcr.io/syzkaller/syzbot
WORKDIR /app

RUN git config --system --add safe.directory '*'
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1

# The artifacts to be used for buildig and running kernels.
ADD https://storage.googleapis.com/syzkaller/images/buildroot-amd64-2025.05.gz /disk-images/buildroot_amd64.gz
RUN gzip -d /disk-images/buildroot_amd64.gz
ADD https://raw.githubusercontent.com/google/syzkaller/refs/heads/master/dashboard/config/linux/upstream-apparmor-kasan.config /kernel-configs/upstream-apparmor-kasan.config

COPY --from=syz-agent-builder /syzkaller/tools/git-cookie-authdaemon /app/git-cookie-authdaemon
COPY --from=syz-agent-builder /syzkaller/syz-agent/run.sh /app/run.sh
RUN chmod +x /app/git-cookie-authdaemon /app/run.sh
COPY --from=syz-agent-builder /syzkaller/bin/syz-agent /app/syz-agent
COPY --from=syz-agent-builder /syzkaller/bin/ /syzkaller/bin/
COPY --from=syz-agent-builder /syzkaller/sys/ /syzkaller/sys/

ENTRYPOINT ["/app/run.sh"]
