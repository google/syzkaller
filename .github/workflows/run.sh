#!/usr/bin/env bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

export HOME="$PWD"
mkdir -p .cache
set -o pipefail
# Run the specified command in syz-env and convert error messages to github format:
# https://help.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-an-error-message
gopath/src/github.com/google/syzkaller/tools/$1 "${@:2}" | \
	sed -E "s#/syzkaller/gopath/src/github.com/google/syzkaller/#\n#g" | \
	sed -E 's#\s*([a-zA-Z0-9._/-]+):([0-9]+):(([0-9]+):)? (.+)#\0\n::error file=\1,line=\2,col=0\4::\5#'
