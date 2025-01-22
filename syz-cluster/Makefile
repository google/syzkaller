# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

build-controller-dev:
	eval $$(minikube docker-env);\
	docker build -t controller-image-local -f ./controller/Dockerfile ../

build-series-tracker-dev:
	eval $$(minikube docker-env);\
	docker build -t series-tracker-local -f ./series-tracker/Dockerfile ../

deploy-series-tracker-dev: build-series-tracker-dev
	@kubectl rollout restart deployment series-tracker

run-series-tracker-dev: build-series-tracker-dev
	./run-local.sh series-tracker

build-web-dashboard-dev:
	eval $$(minikube docker-env);\
	docker build -t web-dashboard-local -f ./dashboard/Dockerfile ../

deploy-web-dashboard-dev: build-web-dashboard-dev
	@kubectl rollout restart deployment web-dashboard

install-dev-config:
	minikube kubectl -- apply -f ./overlays/dev/global-config.yaml

build-db-mgmt-dev:
	eval $$(minikube docker-env);\
	docker build -t db-mgmt-local -f ./db-mgmt/Dockerfile ../

build-triage-step-dev:
	eval $$(minikube docker-env);\
	docker build -t triage-step-local -f ./workflow/triage-step/Dockerfile ../

build-build-step-dev:
	eval $$(minikube docker-env);\
	docker build -t build-step-local -f ./workflow/build-step/Dockerfile ../

build-boot-step-dev:
	eval $$(minikube docker-env);\
	docker build -t boot-step-local -f ./workflow/boot-step/Dockerfile ../

build-go-tests-dev:
	eval $$(minikube docker-env);\
	docker build -t go-tests-local -f Dockerfile.go-tests ../

build-workflow-dev: build-triage-step-dev build-build-step-dev build-boot-step-dev

all-containers: build-controller-dev build-series-tracker-dev build-db-mgmt-dev build-web-dashboard-dev build-workflow-dev

run-go-tests-dev: build-go-tests-dev
	./run-local.sh go-tests

restart-spanner: build-db-mgmt-dev
	minikube addons disable cloud-spanner;
	minikube addons enable cloud-spanner;
	./run-local.sh db-mgmt migrate
