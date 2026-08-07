#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e

# Resolve directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Verify prerequisites
echo "Verifying prerequisites..."

# Create a local bin directory for dependencies we download
BIN_DIR="${SCRIPT_DIR}/bin"
mkdir -p "${BIN_DIR}"
export PATH="${BIN_DIR}:${PATH}"

if [ ! -w /dev/kvm ]; then
    echo "ERROR: /dev/kvm not found or not writable. KVM is required for QEMU driver."
    exit 1
fi

# Check for OVMF (needed by minikube qemu driver)
if [ ! -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    echo "OVMF firmware (/usr/share/OVMF/OVMF_CODE.fd) not found."

    # Check if we have the 4M version to symlink (common on Debian/gLinux)
    if [ -f /usr/share/OVMF/OVMF_CODE_4M.fd ]; then
        echo "Found OVMF_CODE_4M.fd. Creating symlink..."
        sudo ln -sf /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd
        sudo ln -sf /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd || true
    else
        echo "Attempting to install 'ovmf' package..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y ovmf
            if [ -f /usr/share/OVMF/OVMF_CODE_4M.fd ]; then
                echo "Creating symlink after installation..."
                sudo ln -sf /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd
                sudo ln -sf /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd || true
            fi
        else
            echo "ERROR: apt-get not found. Please install 'ovmf' package and ensure /usr/share/OVMF/OVMF_CODE.fd exists."
            exit 1
        fi
    fi

    # Verify again
    if [ ! -f /usr/share/OVMF/OVMF_CODE.fd ]; then
        echo "ERROR: Failed to configure OVMF firmware."
        exit 1
    fi
    echo "OVMF firmware configured successfully."
fi

if ! command -v minikube >/dev/null 2>&1; then
    MINIKUBE_VERSION="v1.38.1"
    echo "minikube not found. Downloading version ${MINIKUBE_VERSION} to ${BIN_DIR}..."
    curl -Lo "${BIN_DIR}/minikube" "https://storage.googleapis.com/minikube/releases/${MINIKUBE_VERSION}/minikube-linux-amd64"
    chmod +x "${BIN_DIR}/minikube"
    echo "minikube downloaded successfully."
fi

if ! command -v kubectl >/dev/null 2>&1; then
    echo "ERROR: kubectl is not installed."
    exit 1
fi

echo "Prerequisites verified."

# Start Minikube with a dedicated profile
PROFILE="syzkube"

echo "Cleaning up existing Minikube profile '${PROFILE}'..."
minikube delete -p "${PROFILE}" || true

echo "Starting Minikube with profile '${PROFILE}'..."
# Start with qemu driver, larger disk, and mount workspace
minikube start -p "${PROFILE}" --driver=qemu --disk-size=80g --memory=16384 --cpus=8 --mount --mount-string="${REPO_ROOT}:/syzkaller"

# Set default profile for convenience
minikube profile "${PROFILE}"

# Verify nested virtualization
echo "Verifying nested virtualization inside Minikube..."
if ! minikube ssh -p "${PROFILE}" "test -e /dev/kvm" >/dev/null 2>&1; then
    echo "ERROR: /dev/kvm not found inside Minikube. Nested virtualization might not be enabled."
    echo "Please ensure your host supports nested virtualization and minikube is configured correctly."
    exit 1
fi
echo "Nested virtualization verified."

# Create namespace
echo "Creating namespace syzkube..."
kubectl create namespace syzkube --dry-run=client -o yaml | kubectl apply -f -

# Deploy fake-gcs-server
echo "Deploying fake-gcs-server..."
kubectl apply -f "${SCRIPT_DIR}/fake_gcs_server.yaml"

echo "Development environment setup complete."
echo "You can check the status of fake-gcs-server with:"
echo "kubectl get pods -n syzkube"
