#!/usr/bin/env bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FAILED=""
FILES=0
for F in $(git ls-files -s | grep -E '^100755' | cut -f 2 | grep -E -v "/gen/"); do
	((FILES+=1))
	if head -n 1 "$F" | grep -E -q '^#!/' && head -n 1 "$F" | grep -E -v -q -e '^#!/bin/sh$' -e '^#!/usr/bin/env '; then
		echo "$F: Non-portable shebang line. Please use /usr/bin/env to locate the interpreter."
		FAILED=1
	fi
done
[ -n "$FAILED" ] && exit 1
echo "$FILES files checked for non-portable shebang lines"
