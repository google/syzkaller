#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e # exit on any problem
set -o pipefail

syzDir=$(mktemp -d)

git clone --depth 1 --branch master --single-branch \
  https://github.com/google/syzkaller $syzDir
cd $syzDir
"$@"
cd -
rm -rf $syzDir
