#!/usr/bin/env bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e

# .github/workflows/ci.yml passes GITHUB_PR_HEAD_SHA and GITHUB_PR_COMMITS for pull requests.
# That's the range we want to check for PRs. If these are not set, we check from the current HEAD
# to the master branch (presumably a local run). If master does not exist (presumably CI run on
# a commit into a fork tree), check HEAD commit only.
GITHUB_PR_HEAD_SHA="${GITHUB_PR_HEAD_SHA:-HEAD}"
if [ "${GITHUB_PR_COMMITS}" == "" ]; then
	GITHUB_PR_COMMITS=`git log --oneline master..${GITHUB_PR_HEAD_SHA} | wc -l`
	if [ "${GITHUB_PR_COMMITS}" == "" ] || [ "${GITHUB_PR_COMMITS}" == "0" ]; then
		GITHUB_PR_COMMITS=1
	fi
fi

COMMITS=0
FAILED=""
HASHES=$(git log --format="%h" -n ${GITHUB_PR_COMMITS} ${GITHUB_PR_HEAD_SHA})
for HASH in ${HASHES}; do
	((COMMITS+=1))
	SUBJECT=$(git show --format="%s" --no-patch ${HASH})
	BODY=$(git show --format="%B" --no-patch ${HASH})
	if ! [[ ${SUBJECT} =~ ^(Revert \"|(([a-z0-9/_.-]+|Makefile|CONTRIBUTORS|README.md)(, )?)+:\ [a-z].+[^.]$) ]]; then
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
echo "$COMMITS commits checked for format style (git log -n ${GITHUB_PR_COMMITS} ${GITHUB_PR_HEAD_SHA})"
if [ "$FAILED" != "" ]; then exit 1; fi
