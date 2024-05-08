#!/usr/bin/env bash
# Copyright 2022 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

go run github.com/vektra/mockery/v2@v2.40.3 --log-level=error "$@"
