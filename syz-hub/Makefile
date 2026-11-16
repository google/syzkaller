# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

include ../tools/version.mk

HUB_IMAGE_NAME ?= local/syz-hub
HUB_IMAGE_TAG ?= latest

.PHONY: hub-container k8s-minikube k8s-prod

KUSTOMIZE ?= kubectl kustomize

hub-container:
	DOCKER_BUILDKIT=1 docker build --build-arg REV="$(REV)" --build-arg GITREVDATE="$(GITREVDATE)" -t $(HUB_IMAGE_NAME):$(HUB_IMAGE_TAG) -f ./Dockerfile ../

k8s-minikube:
	@$(KUSTOMIZE) ./k8s/overlays/minikube/ | sed \
		-e "s~\$${HUB_IMAGE_NAME}~$(HUB_IMAGE_NAME)~g" \
		-e "s~\$${HUB_IMAGE_TAG}~$(HUB_IMAGE_TAG)~g"

k8s-prod:
	@if [ -z "$(HUB_LOAD_BALANCER_IP)" ]; then echo "HUB_LOAD_BALANCER_IP is not set" && exit 1; fi
	@$(KUSTOMIZE) ./k8s/overlays/prod/ | sed \
		-e "s~\$${HUB_IMAGE_NAME}~$(HUB_IMAGE_NAME)~g" \
		-e "s~\$${HUB_IMAGE_TAG}~$(HUB_IMAGE_TAG)~g" \
		-e "s~\$${HUB_LOAD_BALANCER_IP}~'$(HUB_LOAD_BALANCER_IP)'~g"
