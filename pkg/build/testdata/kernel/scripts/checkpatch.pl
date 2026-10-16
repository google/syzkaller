#!/usr/bin/env bash
set -eu
"$(dirname "$0")/check-sandbox" && cat >/dev/null
