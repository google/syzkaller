# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

include ../tools/version.mk

IMAGE_NAME ?= local/syz-agent
IMAGE_TAG ?= latest
GIT_COOKIE_DAEMON ?= 0

.PHONY: container k8s-minikube k8s-prod

container:
	DOCKER_BUILDKIT=1 docker build --build-arg REV="$(REV)" --build-arg GITREVDATE="$(GITREVDATE)" -t $(IMAGE_NAME):$(IMAGE_TAG) -f ./Dockerfile ../

k8s-minikube:
	@if [ -z "$(GOOGLE_API_KEY)" ]; then echo "GOOGLE_API_KEY is not set" && exit 1; fi
	@if [ -z "$(DASHBOARD_KEY)" ]; then echo "DASHBOARD_KEY is not set" && exit 1; fi
	@kubectl kustomize ./k8s/overlays/minikube/ | sed \
		-e "s~\$${IMAGE_NAME}~$(IMAGE_NAME)~g" \
		-e "s~\$${IMAGE_TAG}~$(IMAGE_TAG)~g" \
		-e "s~\$${GOOGLE_API_KEY}~$(GOOGLE_API_KEY)~g" \
		-e "s~\$${DASHBOARD_KEY}~$(DASHBOARD_KEY)~g"

k8s-prod:
	@kubectl kustomize ./k8s/overlays/prod/ | sed \
		-e "s~\$${IMAGE_NAME}~$(IMAGE_NAME)~g" \
		-e "s~\$${IMAGE_TAG}~$(IMAGE_TAG)~g" \
		-e "s~\$${GIT_COOKIE_DAEMON}~$(GIT_COOKIE_DAEMON)~g"
