#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -o pipefail

KUSTOMIZE="go run sigs.k8s.io/kustomize/kustomize/v5@v5.4.1 build"
KUBECONFORM="go run github.com/yannh/kubeconform/cmd/kubeconform@v0.6.4 -strict -summary -ignore-missing-schemas"
KUBELINTER="go run golang.stackrox.io/kube-linter/cmd/kube-linter@v0.8.3 lint --config .kube-linter.yaml"

# Mock env vars
export IMAGE_NAME="local/syz-agent" IMAGE_TAG="latest" GOOGLE_API_KEY="mock" DASHBOARD_KEY="mock" \
       GIT_COOKIE_DAEMON="mock" LORE_RELAY_IMAGE_NAME="mock" LORE_RELAY_IMAGE_TAG="mock" \
       SPANNER_DATABASE_URI="mock" BLOB_STORAGE_GCS_BUCKET="mock" WORKFLOW_ARTIFACTS_BUCKET="mock" \
       IMAGE_PREFIX="local/"

FAILED=0

run_checks() {
	local name=$1
	local target=$2
	local dir=$3
	echo "Checking $name $target..."
	local yaml
	yaml=$(make -C "$dir" -s "$target" KUSTOMIZE="$KUSTOMIZE")
	if [ $? -ne 0 ]; then
		echo "FAILED: $name $target (make failed)"
		FAILED=1
		return
	fi

	if ! echo "$yaml" | $KUBECONFORM; then
		echo "FAILED: $name $target (kubeconform)"
		FAILED=1
	fi

	if ! $KUBELINTER <(echo "$yaml"); then
		echo "FAILED: $name $target (kube-linter)"
		FAILED=1
	fi
}

for target in k8s-minikube k8s-prod-agent k8s-prod-lore; do
	run_checks "syz-agent" "$target" "syz-agent"
done

for target in k8s-config-argo k8s-config-dev k8s-config-test k8s-config-gke-prod k8s-config-gke-staging \
	       migrate-job.yaml send-test-email-job.yaml fetch-kernels-once.yaml; do
	run_checks "syz-cluster" "$target" "syz-cluster"
done

exit $FAILED
