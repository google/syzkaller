#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# This tool uses syz-db-export artifacts.
# See https://github.com/google/syzkaller/tree/master/tools/syz-db-export documentation.

# Check if the target directory is provided as a command line argument.
if [ -z "$1" ]; then
  echo "Usage: $0 <target_directory>"
  exit 1
fi

target_dir="$1"

# Create the target directory if it doesn't exist.
mkdir -p "$target_dir"

# Download the archive to the target directory.
wget -P "$target_dir" https://storage.googleapis.com/artifacts.syzkaller.appspot.com/shared-files/repro-export/upstream.tar.gz

# Extract the archive in the target directory and then delete it.
tar -xzf "$target_dir/upstream.tar.gz" -C "$target_dir" && rm "$target_dir/upstream.tar.gz"

# Create the bin directory inside the target directory.
mkdir -p "$target_dir/bin"

# Compile the programs and count the successfully built ones.
built_count=$(find "$target_dir/export/bugs" -name "*.c" -print0 | \
  xargs -0 -P 128 -I {} sh -c '
    filename=$(basename {} .c)
    flags=""
    if grep "__NR_mmap2" {}; then
      flags="-m32"
    fi
    if gcc {} $flags -static -pthread -o "'"$target_dir"'/bin/$filename" ; then
      echo 1  # Output 1 if compilation is successful
    else
      echo 0  # Output 0 if compilation fails
    fi
  ' | grep "1" | wc -l)

# Count the number of .c files (reproducers).
reproducer_count=$(find "$target_dir/export/bugs" -name "*.c" -print0 | xargs -0 -n1 echo | wc -l)

echo "Downloaded $reproducer_count reproducers."
echo "Successfully built $built_count programs."
