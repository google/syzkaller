#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG_PREFIX="gcr.io/syzkaller"

PUSH=false
if [ "$1" == "--push" ]; then
  PUSH=true
fi

BUILD_ARGS=()
if [ "$PUSH" == "true" ]; then
  BUILD_ARGS=(--platform linux/amd64,linux/arm64 --push)
else
  BUILD_ARGS=(--load)
fi

echo "Building env-base with args: ${BUILD_ARGS[*]}..."
docker buildx build "${BUILD_ARGS[@]}" --file "$DIR/Dockerfile" --target env-base -t "${TAG_PREFIX}/env:base" "$DIR"

echo "Building env-arch with args: ${BUILD_ARGS[*]}..."
docker buildx build "${BUILD_ARGS[@]}" --file "$DIR/Dockerfile" --target env-arch -t "${TAG_PREFIX}/env:arch" "$DIR"

echo "Building env-dashboard with args: ${BUILD_ARGS[*]}..."
docker buildx build "${BUILD_ARGS[@]}" --file "$DIR/Dockerfile" --target env-dashboard -t "${TAG_PREFIX}/env:dashboard" "$DIR"

echo "Building env-full (latest) with args: ${BUILD_ARGS[*]}..."
docker buildx build "${BUILD_ARGS[@]}" --file "$DIR/Dockerfile" --target env-full -t "${TAG_PREFIX}/env:latest" "$DIR"

echo "Building syzbot with args: ${BUILD_ARGS[*]}..."
docker buildx build "${BUILD_ARGS[@]}" --file "$DIR/Dockerfile" --target syzbot -t "${TAG_PREFIX}/syzbot:latest" "$DIR"
