#!/bin/bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

declare -a Op1=("-a 0 " "-a 1 ")
declare -a Op2=("-s 1 " "-s 2 ")
declare -a Op3=("-m " "")
declare -a Op4=("-O encrypt " "-O compression " "")
declare -i dex=0

dir=`dirname $0`
echo $dir

for op1 in "${Op1[@]}"; do
  for op2 in "${Op2[@]}"; do
    for op3 in "${Op3[@]}"; do
      for op4 in "${Op4[@]}"; do
        echo mkfs.f2fs ${op1}${op2}${op3}${op4} disk.raw
        fallocate -l 64M disk.raw
        mkfs.f2fs "${op1}${op2}${op3}${op4}" disk.raw 
        go run "$dir/syz-imagegen/imagegen.go" -image=./disk.raw -fs=f2fs > "$dir/../sys/linux/test/syz_image_mount_f2fs_$dex"
        rm disk.raw
        dex=dex+1
      done
    done
  done
done

