# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

IMAGE_TAG ?= latest
IMAGE_PREFIX ?= local/
SHELL := /bin/bash
GO_FLAGS ?= $(shell make -s -C .. go-flags 2>/dev/null)

include ../tools/version.mk


IMAGES := controller web-dashboard reporter-server series-tracker email-reporter triage-action build-action boot-action fuzz-action retest-action db-mgmt send-test-email

.PHONY: all
all: $(addprefix bin/, $(IMAGES))


define build_image_rules =
  image_name_$(2) := $(IMAGE_PREFIX)$(2):$(IMAGE_TAG)
  dockerfile_$(2) := $(1)/Dockerfile

  bin/$(2):
		go build "$$(GO_FLAGS)" -o ./bin/$(2) $(1)

  build-$(2)-image: build-common-builder
	  @echo "Building $$(image_name_$(2)) (Dockerfile: $$(dockerfile_$(2)))"
	  DOCKER_BUILDKIT=1 docker build --build-arg IMAGE_PREFIX=$(IMAGE_PREFIX) --build-arg IMAGE_TAG=$(IMAGE_TAG) -t $$(image_name_$(2)) -f $$(dockerfile_$(2)) ../

  push-$(2)-image: build-$(2)-image
	  @echo "Pushing $$(image_name_$(2))"
	  docker push $$(image_name_$(2))

endef

.PHONY: build-common-builder
build-common-builder:
	@echo "Building common builder"
	DOCKER_BUILDKIT=1 docker build --build-arg REV="$(REV)" --build-arg GITREVDATE="$(GITREVDATE)" -t $(IMAGE_PREFIX)syz-cluster-build:$(IMAGE_TAG) -f ./Dockerfile.builder ../


$(eval $(call build_image_rules,./controller,controller))
$(eval $(call build_image_rules,./dashboard,web-dashboard))
$(eval $(call build_image_rules,./reporter-server,reporter-server))
$(eval $(call build_image_rules,./series-tracker,series-tracker))
$(eval $(call build_image_rules,./email-reporter,email-reporter))
$(eval $(call build_image_rules,./workflow/triage,triage-action))
$(eval $(call build_image_rules,./workflow/build,build-action))
$(eval $(call build_image_rules,./workflow/fuzz,fuzz-action))
$(eval $(call build_image_rules,./workflow/retest,retest-action))
$(eval $(call build_image_rules,./workflow/boot,boot-action))
$(eval $(call build_image_rules,./tools/db-mgmt,db-mgmt))
$(eval $(call build_image_rules,./tools/send-test-email,send-test-email))

BUILD_TARGETS := $(addsuffix -image, $(addprefix build-, $(IMAGES)))
PUSH_TARGETS := $(addsuffix -image, $(addprefix push-, $(IMAGES)))

.PHONY: all-containers push-all install-dev-config build-go-tests-dev run-go-tests-dev restart-spanner kustomize-dev

all-containers: $(BUILD_TARGETS)

push-all: $(PUSH_TARGETS)

install-dev-config:
	minikube kubectl -- apply -f ./overlays/dev/global-config.yaml

build-go-tests-dev:
	eval $$(minikube docker-env);\
	docker build -t go-tests-local -f Dockerfile.go-tests ../

run-go-tests-dev: build-go-tests-dev
	./run-local.sh go-tests

restart-spanner: build-db-mgmt-image
	kubectl delete pod -l app=cloud-spanner-emulator 2>/dev/null || true
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

k8s-config-local-infra:
	@kubectl kustomize ./overlays/local/common/ | sed $(SED_EXPRESSIONS) | kubectl apply -f -
	@$(MAKE) k8s-config-argo-wait
	@$(MAKE) spanner-emulator-wait

spanner-emulator-wait:
	@kubectl wait --for=condition=available deployment/cloud-spanner-emulator --timeout=120s

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
	@kubectl kustomize ./overlays/local/minikube/ | sed $(SED_EXPRESSIONS)

k8s-config-gke-prod: ensure-spanner-database-uri-env ensure-blob-storage-env ensure-workflow-artifacts-bucket
	@kubectl kustomize ./overlays/gke/prod/ | sed $(SED_EXPRESSIONS)

k8s-config-gke-staging: ensure-spanner-database-uri-env ensure-blob-storage-env ensure-workflow-artifacts-bucket
	@kubectl kustomize ./overlays/gke/staging/ | sed $(SED_EXPRESSIONS)

migrate-job.yaml:
	@cat tools/db-mgmt/migrate-job.yaml | sed $(SED_EXPRESSIONS)

migrate-local:
	@kubectl apply -f overlays/local/common/global-config-env.yaml
	@$(MAKE) migrate

migrate:
	@echo "Starting database migration..."
	@job_name=$$(make -s migrate-job.yaml | kubectl create -o jsonpath='{.metadata.name}' -f -) && \
	echo "Waiting for job $$job_name to complete..." && \
	kubectl wait --for=condition=complete "job/$$job_name" --timeout=120s

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
