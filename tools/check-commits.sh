#!/usr/bin/env bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e

# GITHUB_PR_BASE_SHA is exported in .github/workflows/ci.yml for pull requests.
# If it is not set, check against refs/heads/master (presumably a local run),
# otherwise skip the checks (presumably CI run on a fork commit).
if [ "${GITHUB_PR_BASE_SHA}" == "" ]; then
	GITHUB_PR_BASE_SHA="refs/heads/master"
	HAVE_MASTER=0
	git show-ref ${GITHUB_PR_BASE_SHA} 1>/dev/null 2>&1 || HAVE_MASTER=$?
	if [[ HAVE_MASTER -ne 0 ]]; then
		echo "skipping commit checks: GITHUB_PR_BASE_SHA is not set and ${GITHUB_PR_BASE_SHA} does not exist"
		exit 0
	fi
fi

COMMITS=0
FAILED=""
HASHES=$(git log --format="%h" ${GITHUB_PR_BASE_SHA}..HEAD)
for HASH in ${HASHES}; do
	((COMMITS+=1))
	SUBJECT=$(git show --format="%s" --no-patch ${HASH})
	BODY=$(git show --format="%B" --no-patch ${HASH})
	if ! [[ ${SUBJECT} =~ ^(([a-z0-9/_.-]+|Makefile|CONTRIBUTORS|README.md)(, )?)+:\ [a-z].+[^.]$ ]]; then
		echo "##[error]Wrong commit subject format: '${SUBJECT}'.\
 Please use 'main/affected/package: short change description'.\
 See docs/contributing.md for details."
		FAILED="1"
	fi
	LONGLINE='[^\
]{121}'
	if [[ ${BODY} =~ ${LONGLINE} ]]; then
		echo "##[error]Please limit commit description line length to 120 characters."
		echo "${BODY}"
		FAILED="1"
	fi
done
if [ "$FAILED" != "" ]; then exit 1; fi
echo "$COMMITS commits checked for format style"
