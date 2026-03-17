#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

if ! command -v kind &> /dev/null; then
    echo "ERROR: kind is not installed." >&2
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo "ERROR: kubectl is not installed." >&2
    exit 1
fi

CLUSTER_NAME="syz-cluster-test"
export KUBECONFIG="$DIR/.test-kubeconfig"

function cleanup {
    local exit_code=$?
    echo "=== Cleaning up ===" >&2
    if [ $exit_code -ne 0 ]; then
        echo "=== TEST FAILED ===" >&2
        echo "Dumping pod status:" >&2
        kubectl get pods -A >&2 || true
        echo "Dumping pod logs for all pods in default namespace:" >&2
        for pod in $(kubectl get pods -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
            echo "--- Logs for $pod ---" >&2
            kubectl logs "$pod" --all-containers >&2 || true
            kubectl describe pod "$pod" >&2 || true
        done
        echo "Leaving cluster intact for debugging. Run 'kind delete cluster --name $CLUSTER_NAME' manually." >&2
    else
        kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
        rm -f "$KUBECONFIG"
    fi
}

trap cleanup EXIT

echo "=== Cleaning up existing kind cluster ==="
kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true

echo "=== Starting kind cluster ==="
kind create cluster --name "$CLUSTER_NAME"

echo "=== Building container images ==="
make all-containers IMAGE_PREFIX="local_smoke/" SMOKE_TEST="1"

echo "=== Loading container images into kind ==="
# Find all newly built local_smoke/ images (excluding the builder image itself) and load them in a single batch
IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^local_smoke/' | grep -v 'syz-cluster-build')
echo "Loading images..."
kind load docker-image $IMAGES --name "$CLUSTER_NAME"

echo "=== Deploying Local Infrastructure ==="
kubectl create namespace argo
make k8s-config-local-infra IMAGE_PREFIX="local_smoke/"

echo "=== Running Database Migrations ==="
make migrate-local IMAGE_PREFIX="local_smoke/"

echo "=== Deploying syz-cluster (Test Config) ==="
make k8s-config-test IMAGE_PREFIX="local_smoke/" | kubectl apply -f -

echo "=== Verification ==="

echo "Waiting for core deployments to become available..."
kubectl wait --for=condition=available deployment/controller-deployment deployment/web-dashboard deployment/reporter-server-deployment deployment/series-tracker --timeout=120s

echo "Verifying web-dashboard HTTP response..."
kubectl port-forward svc/web-dashboard-service 8080:80 &
PORT_FORWARD_PID=$!

# Wait for port-forward to establish
sleep 3

# Perform curl and check for HTTP 200
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ || echo "FAILED")
if [ "$HTTP_STATUS" != "200" ]; then
    echo "Web dashboard returned HTTP status: $HTTP_STATUS (expected 200)"
    kill $PORT_FORWARD_PID
    exit 1
fi
echo "Web dashboard returned HTTP 200!"
kill $PORT_FORWARD_PID

echo "=== Smoke test passed! ==="
exit 0
