#!/usr/bin/env bash
set -eu
# The kernel tree must be mounted read-only for checkpatch.
tree="$(dirname "$0")/.."
! touch "$tree/escape" 2>/dev/null
! touch "$tree/.git/escape" 2>/dev/null
"$(dirname "$0")/check-sandbox" && cat >/dev/null
