#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -euo pipefail

test_path="$1"
shift
go_flags="$@"

if [ -z "${TEST_SHARD:-}" ]; then
	CGO_ENABLED=1 go test $go_flags "$test_path"
	exit 0
fi

IFS='/' read -r index_str total_str <<< "$TEST_SHARD"

if [ -z "$index_str" ] || [ -z "$total_str" ]; then
	echo "Invalid TEST_SHARD format: $TEST_SHARD. Expected 'index/total' (e.g. 1/5)."
	exit 1
fi

shard_index=$((index_str - 1))
shard_count=$total_str

if [ $shard_index -lt 0 ] || [ $shard_index -ge $shard_count ]; then
	echo "Invalid shard index: $shard_index. Must be between 0 and $((shard_count - 1))."
	exit 1
fi

if [ "$test_path" = "./..." ]; then
	# For full tree tests, use package-based sharding to avoid building the entire tree.
	packages=$(CGO_ENABLED=1 go list ./... | awk "NR % $shard_count == $shard_index")
	if [ -n "$packages" ]; then
		CGO_ENABLED=1 go test $go_flags $packages
	fi
else
	# For specific paths (like dashboard), use name-based sharding for fine-grained parallelization.
	tests=$(CGO_ENABLED=1 go test -list . "$test_path" | grep ^Test | \
		awk "NR % $shard_count == $shard_index" | paste -sd "|")

	if [ -n "$tests" ]; then
		CGO_ENABLED=1 go test $go_flags -run "^($tests)$" "$test_path"
	else
		echo "No tests selected for shard $TEST_SHARD"
	fi
fi
