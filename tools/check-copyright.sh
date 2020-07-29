#!/usr/bin/env bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FILES=0
FAILED=""
for F in $(find . -name "*.go" -o -name "*.sh" -o -name "*.cc" -o -name "*.h" \
	-o -name "*.S" -o -name "*.py" -o -name "*.yml" -o -name "*.yaml" \
	-o \( -path "./sys/*/*.txt" \) | egrep -v "/vendor/|/gen/"); do
	((FILES+=1))
	cat $F | tr '\n' '_' | egrep "(//|#) Copyright 20[0-9]{2}(/20[0-9]{2})? syzkaller project authors\. All rights reserved\._(//|#) Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file\." >/dev/null
	if [ $? -eq 0 ]; then continue; fi
	# Ignore auto-generated files.
	egrep "^(//|#) Code generated .* DO NOT EDIT\\.|(WARNING: This file is machine generated)" $F >/dev/null
	if [ $? -eq 0 ]; then continue; fi
	# Ignore untracked files.
	git ls-files --error-unmatch $F >/dev/null 2>&1
	if [ $? -ne 0 ]; then continue; fi
	echo "$F:1:1: The file does not have the standard copyright statement (please add)."
	FAILED="1"
done
if [ "$FAILED" != "" ]; then exit 1; fi
echo "$FILES files checked for copyright statement"
