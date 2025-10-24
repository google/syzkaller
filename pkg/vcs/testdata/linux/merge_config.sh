#!/usr/bin/env bash

# merge_config.sh -m -O outdir baseline kernelAdditionsConfig
OUTDIR=$3

echo `cat $4` > $OUTDIR/.config
echo `cat $5` >> $OUTDIR/.config

exit 0
