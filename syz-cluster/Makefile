# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

IMAGE_TAG ?= latest
IMAGE_PREFIX ?= local/
SHELL := /bin/bash

define build_image_rules =
  image_name_$(2) := $(IMAGE_PREFIX)$(2):$(IMAGE_TAG)
  dockerfile_$(2) := $(1)/Dockerfile

  build-$(2):
	  @echo "Building $$(image_name_$(2)) (Dockerfile: $$(dockerfile_$(2)))"
	  DOCKER_BUILDKIT=1 docker build -t $$(image_name_$(2)) -f $$(dockerfile_$(2)) ../

  push-$(2): build-$(2)
	  @echo "Pushing $$(image_name_$(2))"
	  docker push $$(image_name_$(2))

endef

$(eval $(call build_image_rules,./controller,controller))
$(eval $(call build_image_rules,./dashboard,web-dashboard))
$(eval $(call build_image_rules,./reporter-server,reporter-server))
$(eval $(call build_image_rules,./series-tracker,series-tracker))
$(eval $(call build_image_rules,./db-mgmt,db-mgmt))
$(eval $(call build_image_rules,./email-reporter,email-reporter))
$(eval $(call build_image_rules,./workflow/triage-step,triage-step))
$(eval $(call build_image_rules,./workflow/build-step,build-step))
$(eval $(call build_image_rules,./workflow/fuzz-step,fuzz-step))
$(eval $(call build_image_rules,./workflow/boot-step,boot-step))

IMAGES := controller web-dashboard reporter-server series-tracker db-mgmt triage-step build-step boot-step fuzz-step
BUILD_TARGETS := $(addprefix build-, $(IMAGES))
PUSH_TARGETS := $(addprefix push-, $(IMAGES))

.PHONY: build-all push-all deploy-series-tracker run-series-tracker install-dev-config build-go-tests-dev run-go-tests-dev restart-spanner kustomize-dev

build-all: $(BUILD_TARGETS)

push-all: $(PUSH_TARGETS)

deploy-series-tracker: build-series-tracker
	@kubectl rollout restart deployment series-tracker

run-series-tracker: build-series-tracker
	./run-local.sh series-tracker

deploy-web-dashboard: build-web-dashboard
	@kubectl rollout restart deployment web-dashboard

install-dev-config:
	minikube kubectl -- apply -f ./overlays/dev/global-config.yaml

build-go-tests-dev:
	eval $$(minikube docker-env);\
	docker build -t go-tests-local -f Dockerfile.go-tests ../

run-go-tests-dev: build-go-tests-dev
	./run-local.sh go-tests

restart-spanner: build-db-mgmt
	minikube addons disable cloud-spanner;
	minikube addons enable cloud-spanner;
	./run-local.sh db-mgmt migrate


SUBSTITUTE_VARS := '$$IMAGE_PREFIX $$IMAGE_TAG $$SPANNER_DATABASE_URI $$BLOB_STORAGE_GCS_BUCKET $$WORKFLOW_ARTIFACTS_BUCKET'

k8s-config-dev:
	@kubectl kustomize ./overlays/minikube/ | IMAGE_PREFIX=${IMAGE_PREFIX} IMAGE_TAG=${IMAGE_TAG} envsubst ${SUBSTITUTE_VARS}

k8s-config-gke: ensure-spanner-database-uri-env ensure-blob-storage-env ensure-workflow-artifacts-bucket
	@kubectl kustomize ./overlays/gke/ | IMAGE_PREFIX=${IMAGE_PREFIX} IMAGE_TAG=${IMAGE_TAG} envsubst ${SUBSTITUTE_VARS}

migrate-job.yaml: ensure-spanner-database-uri-env
	@cat db-mgmt/migrate-job.yaml | IMAGE_PREFIX=${IMAGE_PREFIX} IMAGE_TAG=${IMAGE_TAG} envsubst

ensure-spanner-database-uri-env:
	@if [ -z "${SPANNER_DATABASE_URI}" ]; then \
                echo "Error: SPANNER_DATABASE_URI must be defined."; \
                exit 1; \
        fi

ensure-blob-storage-env:
	@if [ -z "${BLOB_STORAGE_GCS_BUCKET}" ]; then \
                echo "Error: BLOB_STORAGE_GCS_BUCKET must be defined."; \
                exit 1; \
        fi

ensure-workflow-artifacts-bucket:
	@if [ -z "${WORKFLOW_ARTIFACTS_BUCKET}" ]; then \
                echo "Error: WORKFLOW_ARTIFACTS_BUCKET must be defined."; \
                exit 1; \
        fi
