#!/usr/bin/env bash

export HOME="$PWD"
mkdir -p .cache
set -o pipefail
# Run the specified command and convert error messages to github format:
# https://help.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-an-error-message
$1 "${@:2}" | \
	sed -E 's#\s*([a-zA-Z0-9._/-]+):([0-9]+):(([0-9]+):)? (.+)#\0\n::error file=\1,line=\2,col=0\4::\5#'
