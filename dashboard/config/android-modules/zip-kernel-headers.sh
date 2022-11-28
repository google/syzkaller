#!/usr/bin/env bash

# Copyright 2022 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Zips kernel headers given a root kernel directory.

# $1 Kernel common dir
KERNEL_COMMON_DIR=$1
KERNEL_HEADERS_TAR=${KERNEL_COMMON_DIR}/kernel-headers.tar.gz
echo " Copying kernel headers to ${KERNEL_HEADERS_TAR}"
cd $KERNEL_COMMON_DIR
  find arch include $KERNEL_COMMON_DIR -name *.h -print0               \
          | tar -czf $KERNEL_HEADERS_TAR                     \
            --absolute-names                                 \
            --dereference                                    \
            --transform "s,.*$KERNEL_COMMON_DIR,,"                     \
            --transform "s,^,kernel-headers/,"               \
            --null -T -
