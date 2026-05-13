#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FAILED=""
for f in $(find . -name "*.sql"); do
	if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then
		echo "$f:1:1: No newline at the end of the file."
		FAILED="1"
	fi
done

if [ "$FAILED" != "" ]; then exit 1; fi
