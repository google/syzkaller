#!/usr/bin/env bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FILES=0
FAILED=""
RE="[[:space:]]$"
LAST_EMPTY=""
for F in $(find . -name "*.sh" -o -name "*.S" -o -name "*.py" -o -name "*.yml" -o -name "*.yaml" -o -name "*.md" | \
		egrep -v "/gen/"); do
	((FILES+=1))
	L=0
	while IFS= read -r LINE; do
		((L+=1))
		if [[ $LINE =~ $RE ]]; then
			echo "$F:$L:1: Trailing whitespace at the end of the line. Please remove."
			echo "$LINE"
			FAILED="1"
		fi
		LAST_EMPTY=""
		if [ "$LINE" == "" ]; then
			LAST_EMPTY="1"
		fi
	done < "$F"
	if [ "$LAST_EMPTY" != "" ]; then
		echo "$F:$L:1: Trailing empty line at the end of the file. Please remove."
		FAILED="1"
	fi
done
if [ "$FAILED" != "" ]; then exit 1; fi
echo "$FILES files checked for whitespaces"
