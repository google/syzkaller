#!/bin/bash
# Copyright 2020 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Currently disabled
# declare -a Op1=("-d raid0 " "-d raid1 " "-d raid5 " "-d raid6 " "-d raid10 " "-d single " "-d dup ")
declare -a Op1=("-M " "")
declare -a Op2=("-O mixed-bg " "-O extref " "-O raid56 " "-O no-holes " "-O raid1c34 ")
declare -a Op3=("-K " "")
declare -a Op4=("--csum crc32c " "--csum xxhash " "--csum sha256 " "--csum blake2 ")
declare -i dex=0

dir=`dirname $0`
echo $dir

for op1 in "${Op1[@]}"; do
  for op2 in "${Op2[@]}"; do
    for op3 in "${Op3[@]}"; do
      for op4 in "${Op4[@]}"; do
        echo mkfs.btrfs ${op1}${op2}${op3}${op4} disk.raw
        fallocate -l 128M disk.raw
        mkfs.btrfs ${op1}${op2}${op3}${op4} disk.raw 
        go run "$dir/syz-imagegen/imagegen.go" -image=./disk.raw -fs=btrfs > "$dir/../sys/linux/test/syz_image_mount_btrfs_$dex"
        rm disk.raw
        dex=dex+1
      done
    done
  done
done

