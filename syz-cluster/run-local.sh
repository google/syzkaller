#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

if [ -z "$1" ]; then
  echo "Error: No command/service name provided."
  exit 1
fi

name="$1"
shift

alias kubectl="minikube kubectl --"
# Clean up in case the run comand was prematurely aborted.
# TODO: find out how to rely on envs from overlays/dev/global-config.yaml.
kubectl delete pod run-local >/dev/null 2>&1 || true
kubectl run run-local --image="$name-local" \
  --image-pull-policy=Never \
  --restart=Never \
  --env="SPANNER_EMULATOR_HOST=cloud-spanner-emulator:9010" \
  --env="SPANNER_DATABASE_URI=projects/my-project/instances/my-instance/databases/db" \
  --env="LOCAL_BLOB_STORAGE_PATH=/tmp/blobs/" \
  --rm \
  --attach -- "$@"
