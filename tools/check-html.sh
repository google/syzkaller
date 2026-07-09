#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

FILES=0
FAILED=""
for F in $(git ls-files '*.html'); do
	((FILES+=1))
	TABS=`cat $F | grep "	"  | wc -l`
	# templates.html uses several spaces to format commit info using fixed-width font.
	SPACES=`cat $F | grep -v "Commit.Date" | grep "  "  | wc -l`
	if [ "$TABS" -eq "0" ] || [ "$SPACES" -eq "0" ]; then continue; fi
	echo "$F:1:1: Uses both spaces ($SPACES) and tabs ($TABS) for formatting. Use either one of these."
	FAILED="1"
done
if [ "$FAILED" != "" ]; then exit 1; fi
echo "$FILES HTML files checked for formatting"
