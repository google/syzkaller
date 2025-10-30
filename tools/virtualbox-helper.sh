#!/usr/bin/env bash
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
#
# Author: Kuzey Arda Bulut <kuzey@kuzeyardabulut.com>
set -e

SOCKET="${1}"
nc -U "$SOCKET" -w 60
