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
$(eval $(call build_image_rules,./email-reporter,email-reporter))
$(eval $(call build_image_rules,./workflow/triage,triage-action))
$(eval $(call build_image_rules,./workflow/build,build-action))
$(eval $(call build_image_rules,./workflow/fuzz,fuzz-action))
$(eval $(call build_image_rules,./workflow/boot,boot-action))
$(eval $(call build_image_rules,./tools/db-mgmt,db-mgmt))
$(eval $(call build_image_rules,./tools/send-test-email,send-test-email))

IMAGES := controller web-dashboard reporter-server series-tracker db-mgmt triage-action build-action boot-action fuzz-action send-test-email email-reporter
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

# It takes some time for K8S to set up Argo CRDs, so if we `kubectl apply` everything at once, it will not
# work on the first attempt.
# The following two targets facilitate CI/CD:
# - k8s-config-argo installs Argo workflows.
# - k8s-config-argo-wait awaits untill all CRDs are ready.
k8s-config-argo:
	@kubectl kustomize ./overlays/common/argo/

k8s-config-argo-wait:
	@kubectl wait --for condition=established --timeout=60s crd/cronworkflows.argoproj.io
	@kubectl wait --for condition=established --timeout=60s crd/workflows.argoproj.io

escape_sed_replacement = \
    $(shell printf '%s' '$(subst ','\'',$(1))' | \
    sed -e 's~\\~\\\\~g' \
        -e 's~&~\\&~g' \
        -e 's~\$$~\\$$~g' \
        -e 's~/~\\/~g' \
    )

SED_EXPRESSIONS := \
    -e "s~\$${IMAGE_PREFIX}~$(call escape_sed_replacement,${IMAGE_PREFIX})~g" \
    -e "s~\$${IMAGE_TAG}~$(call escape_sed_replacement,${IMAGE_TAG})~g" \
    -e "s~\$${SPANNER_DATABASE_URI}~$(call escape_sed_replacement,${SPANNER_DATABASE_URI})~g" \
    -e "s~\$${WORKFLOW_ARTIFACTS_BUCKET}~$(call escape_sed_replacement,${WORKFLOW_ARTIFACTS_BUCKET})~g" \
    -e "s~\$${BLOB_STORAGE_GCS_BUCKET}~$(call escape_sed_replacement,${BLOB_STORAGE_GCS_BUCKET})~g" \

k8s-config-dev:
	@kubectl kustomize ./overlays/minikube/ | sed $(SED_EXPRESSIONS)

k8s-config-gke-prod: ensure-spanner-database-uri-env ensure-blob-storage-env ensure-workflow-artifacts-bucket
	@kubectl kustomize ./overlays/gke/prod/ | sed $(SED_EXPRESSIONS)

k8s-config-gke-staging: ensure-spanner-database-uri-env ensure-blob-storage-env ensure-workflow-artifacts-bucket
	@kubectl kustomize ./overlays/gke/staging/ | sed $(SED_EXPRESSIONS)

migrate-job.yaml:
	@cat tools/db-mgmt/migrate-job.yaml | sed $(SED_EXPRESSIONS)

send-test-email-job.yaml:
	@cat tools/send-test-email/job.yaml | sed $(SED_EXPRESSIONS)

fetch-kernels-once.yaml:
	@cat kernel-disk/fetch-kernels-once.yaml

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
