#!/bin/ksh

# Run this script after editing *.txt in this directory to recreate
# the derived artifacts.
set -e

FILES=$((cd sys/openbsd; find . -type f -name '*.txt') | sed 's,./,,')

gmake generate_go
gmake bin/syz-sysgen
gmake bin/syz-extract

rm -rf sys/openbsd/gen
./bin/syz-extract -build -os openbsd -arch amd64 -sourcedir /usr/src $FILES

./bin/syz-sysgen
