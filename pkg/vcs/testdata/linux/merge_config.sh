#!/bin/bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# merge_config.sh -m -O outdir baseline kernelAdditionsConfig
OUTDIR=$3

echo `cat $4` > $OUTDIR/.config
echo `cat $5` >> $OUTDIR/.config

exit 0
