#!/usr/bin/env bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FILES=0
FAILED=""
shopt -s nocasematch
for F in $(find . -name "*.go" -o -name "*.sh" -o -name "*.cc" -o -name "*.md" \
	-o -name "*.S" -o -name "*.py" -o -name "*.yml" -o -name "*.yaml" | \
	egrep -v "/vendor/|/gen/|executor/syscalls.h|pkg/csource/generated.go|tools/check-language.sh"); do
	((FILES+=1))
	L=0
	while IFS= read -r LINE; do
		((L+=1))
		if [[ $LINE =~ (slave|blacklist|whitelist) ]]; then
			if [[ $LINE =~ bond_enslave ]]; then
				continue
			fi
			SUGGESTIONS="block/allow/ignore/skip"
			if [[ $LINE =~ (slave) ]]; then
				SUGGESTIONS="leader/follower/coordinator/worker/parent/helper"
			fi
			echo "$F:$L:1: Please use more respectful terminology, consider using ${SUGGESTIONS} instead." \
				"See https://tools.ietf.org/id/draft-knodel-terminology-01.html for more info."
			echo "$LINE"
			FAILED="1"
		fi
	done < "$F"
done
if [ "$FAILED" != "" ]; then exit 1; fi
echo "$FILES files checked" >&2
