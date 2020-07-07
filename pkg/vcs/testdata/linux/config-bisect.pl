#!/bin/bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
# config-bisect.pl -l ctx.git.dir -r -b ctx.git.dir kernelBaselineConfig kernelConfig

set -eu

if [ "$3" == "-r" ]
then
    baseline=`cat $6`
    outdir=$5
    echo $baseline > $outdir/.config
    exit 0
fi

# config-bisect.pl -l ctx.git.dir -b ctx.git.dir kernelBaselineConfig kernelConfig verdict
baseline=`cat $5`

# Test baseline file contains string CONFIG_FAILING -> fail
if [ "$baseline" == "CONFIG_FAILING=y" ]
then
    exit 1
fi

# Generate end results which "reproduces" the crash
if [ $baseline == "CONFIG_REPRODUCES_CRASH=y" ]
then
    echo "%%%%%%%% FAILED TO FIND SINGLE BAD CONFIG %%%%%%%%"
    echo "Hmm, can't make any more changes without making good == bad?"
    echo "Difference between good (+) and bad (-)"
    echo "REPRODUCES_CRASH n -> y"
    echo "-DISABLED_OPTION=n"
    echo "+ONLY_IN_ORIGINAL_OPTION=y"
    echo "See good and bad configs for details:"
    echo "good: /mnt/work/config_bisect_evaluation/out/config_bisect/kernel.baseline_config.tmp"
    echo "bad:  /mnt/work/config_bisect_evaluation/out/config_bisect/kernel.config.tmp"
    echo "%%%%%%%% FAILED TO FIND SINGLE BAD CONFIG %%%%%%%%"
    exit 2
fi

# Generate end result which doesn't "reproduce" the crash
if [ $baseline == "CONFIG_NOT_REPRODUCE_CRASH=y" ]
then
    echo "%%%%%%%% FAILED TO FIND SINGLE BAD CONFIG %%%%%%%%"
    echo "Hmm, can't make any more changes without making good == bad?"
    echo "Difference between good (+) and bad (-)"
    echo "NOT_REPRODUCE_CRASH n -> y"
    echo "See good and bad configs for details:"
    echo "good: /mnt/work/config_bisect_evaluation/out/config_bisect/kernel.baseline_config.tmp"
    echo "bad:  /mnt/work/config_bisect_evaluation/out/config_bisect/kernel.config.tmp"
    echo "%%%%%%%% FAILED TO FIND SINGLE BAD CONFIG %%%%%%%%"
    exit 2
fi
