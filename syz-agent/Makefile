# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

include ../tools/version.mk

IMAGE_NAME ?= local/syz-agent
IMAGE_TAG ?= latest

.PHONY: container
container:
	DOCKER_BUILDKIT=1 docker build --build-arg REV="$(REV)" --build-arg GITREVDATE="$(GITREVDATE)" -t $(IMAGE_NAME):$(IMAGE_TAG) -f ./Dockerfile ../
