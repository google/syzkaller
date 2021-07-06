// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// As we use syscall package:
//go:build linux
// +build linux

// syz-imagegen generates sys/linux/test/syz_mount_image_* test files.
// It requires the following packages to be installed:
//	f2fs-tools, xfsprogs, reiserfsprogs, gfs2-utils, ocfs2-tools, genromfs, erofs-utils, makefs, udftools,
//	mtd-utils, nilfs-tools, squashfs-tools, genisoimage.
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

// FileSystem represents one file system.
// Each FileSystem produces multiple images, see MkfsFlagCombinations and Image type.
type FileSystem struct {
	// Name of the file system. Needs to match syz_mount_image$NAME name.
	Name string
	// Imagegen autodetects size for images starting from MinSize and then repeatedly doubling it if mkfs fails.
	MinSize int
	// Don't populate this image with files (can't mount read-write).
	ReadOnly bool
	// These flags are always appended to mkfs as is.
	MkfsFlags []string
	// Generate images for all possible permutations of these flag combinations.
	MkfsFlagCombinations [][]string
	// Custom mkfs invocation, if nil then mkfs.name is invoked in a standard way.
	Mkfs func(image *Image) error
}

// nolint:lll
var fileSystems = []FileSystem{
	{
		Name:      "f2fs",
		MinSize:   64 << 20,
		MkfsFlags: []string{"-e cold"},
		MkfsFlagCombinations: [][]string{
			{"-a 0", "-a 1"},
			{"-s 1", "-s 2"},
			{"", "-m"},
			{
				"",
				"-O encrypt",
				"-O extra_attr",
				"-O extra_attr -O flexible_inline_xattr -O inode_checksum -O inode_crtime -O project_quota",
			},
		},
	},
	{
		Name:    "btrfs",
		MinSize: 16 << 20,
		MkfsFlagCombinations: [][]string{
			{"", "-M"},
			{"", "-K"},
			{"--csum crc32c", "--csum xxhash", "--csum sha256", "--csum blake2"},
			{"--nodesize 4096 -O mixed-bg", "-O extref", "-O raid56", "-O no-holes", "-O raid1c34"},
		},
	},
	{
		Name:      "vfat",
		MinSize:   64 << 10,
		MkfsFlags: []string{"-n", "SYZKALLER"},
		MkfsFlagCombinations: [][]string{
			{"", "-a -I"},
			{"", "-h 3 -f 4"},
			{"-s 1", "-s 8", "-s 128"},
			{
				"-F 12 -r 64 -S 512",
				"-F 12 -r 64 -S 2048 -A",
				"-F 16 -r 112 -S 512",
				"-F 32 -r 768 -S 512",
				"-F 32 -r 768 -S 2048 -A",
			},
		},
	},
	{
		Name:      "exfat",
		MinSize:   128 << 10,
		MkfsFlags: []string{"-i", "0x12341234"},
		MkfsFlagCombinations: [][]string{
			{"", "-p 3"},
		},
	},
	{
		Name:      "bfs",
		MinSize:   4 << 10,
		ReadOnly:  true, // creating files fails with ENOPERM
		MkfsFlags: []string{"-V", "syzkal", "-F", "syzkal"},
		MkfsFlagCombinations: [][]string{
			{"-N 48", "-N 127", "-N 512"},
		},
	},
	{
		Name:      "xfs",
		MinSize:   16 << 20,
		MkfsFlags: []string{"-l", "internal"},
		MkfsFlagCombinations: [][]string{
			// Most XFS options are inter-dependent and total number of combinations is huge,
			// so we enumerate some combinations that don't produce errors.
			{
				"-b size=512 -i size=256  -d agcount=2 -m crc=0 -m finobt=0 -m rmapbt=0 -m reflink=0 -i sparse=0 -i maxpct=25  -i attr=1 -i projid32bit=0 -l lazy-count=0",
				"-b size=2k  -i size=1024 -d agcount=2 -m crc=0 -m finobt=0 -m rmapbt=0 -m reflink=0 -i sparse=0 -i maxpct=5   -i attr=1 -i projid32bit=0 -l lazy-count=1",
				"-b size=4k  -i size=2048 -d agcount=4 -m crc=0 -m finobt=0 -m rmapbt=0 -m reflink=0 -i sparse=0 -i maxpct=90  -i attr=2 -i projid32bit=1 -l lazy-count=0",
				"-b size=1k  -i size=512  -d agcount=2 -m crc=1 -m finobt=0 -m rmapbt=0 -m reflink=0 -i sparse=0 -i maxpct=20  -i attr=2 -i projid32bit=1 -l lazy-count=1",
				"-b size=2k  -i size=1024 -d agcount=4 -m crc=1 -m finobt=1 -m rmapbt=1 -m reflink=1 -i sparse=0 -i maxpct=3   -i attr=2 -i projid32bit=1 -l lazy-count=1",
				"-b size=4k  -i size=2048 -d agcount=1 -m crc=1 -m finobt=0 -m rmapbt=1 -m reflink=0 -i sparse=0 -i maxpct=100 -i attr=2 -i projid32bit=1 -l lazy-count=1",
				"-b size=1k  -i size=512  -d agcount=2 -m crc=1 -m finobt=0 -m rmapbt=0 -m reflink=0 -i sparse=1 -i maxpct=99  -i attr=2 -i projid32bit=1 -l lazy-count=1",
				"-b size=2k  -i size=1024 -d agcount=1 -m crc=1 -m finobt=1 -m rmapbt=1 -m reflink=1 -i sparse=1 -i maxpct=50  -i attr=2 -i projid32bit=1 -l lazy-count=1",
				"-b size=4k  -i size=1024 -d agcount=1 -m crc=1 -m finobt=1 -m rmapbt=0 -m reflink=1 -i sparse=1 -i maxpct=10  -i attr=2 -i projid32bit=1 -l lazy-count=1",
			},
			{"-l sunit=16", "-l sunit=64", "-l sunit=128", "-l su=8k"},
		},
	},
	{
		Name:    "minix",
		MinSize: 16 << 10,
		MkfsFlagCombinations: [][]string{
			{
				"-1 -n 14",
				"-1 -n 30",
				"-2 -n 14",
				"-2 -n 30",
				"-3 -n 60",
			},
			{"-i 16", "-i 64", "-i 1024"},
		},
	},
	{
		Name:      "reiserfs",
		MinSize:   4 << 20,
		ReadOnly:  true, // mounting this crashes my host kernel
		MkfsFlags: []string{"-f", "-f", "-l", "syzkaller"},
		MkfsFlagCombinations: [][]string{
			{"-b 4096", "-b 8192"},
			{"-h r5", "-h rupasov", "-h tea"},
			{"--format 3.5", "--format 3.6 -u 12312312-1233-1233-1231-123413412412"},
			{
				"-s 513",
				"-s 8193 -t 128",
				"-s 8193 -t 1024",
				"-s 15749 -t 128",
				"-s 15749 -t 1024",
			},
		},
	},
	{
		Name:      "jfs",
		MinSize:   16 << 20,
		MkfsFlags: []string{"-q"},
		MkfsFlagCombinations: [][]string{
			{"", "-s 1M"},
			{"", "-O"},
		},
	},
	{
		Name:      "ntfs",
		MinSize:   1 << 20,
		MkfsFlags: []string{"-f", "-F", "-L", "syzkaller"},
		MkfsFlagCombinations: [][]string{
			{
				"-s 256 -c 256",
				"-s 256 -c 2048",
				"-s 512 -c 1024",
				"-s 512 -c 4096",
				"-s 1024 -c 4096",
				"-s 1024 -c 65536",
				"-s 2048 -c 2048",
				"-s 2048 -c 4096",
				"-s 4096 -c 4096",
				"-s 4096 -c 131072",
			},
			{"", "-I"},
		},
	},
	{
		Name:      "ext4",
		MinSize:   64 << 10,
		MkfsFlags: []string{"-L", "syzkaller", "-U", "clear", "-E", "test_fs"},
		MkfsFlagCombinations: [][]string{
			{"-t ext2", "-t ext3", "-t ext4"},
			// Total number of combinations is too large and there are lots of dependencies between flags,
			// so we create just few permutations generated with fair dice rolls.
			// TODO: We also need to give some combination of -E encoding=utf8/utf8-12.1 and -E encoding_flags=strict,
			// but mounting such fs on my host fails with "Filesystem with casefold feature cannot be mounted without CONFIG_UNICODE".
			{
				"-b 1024 -I 128 -E lazy_itable_init=0 -E num_backup_sb=0 -E packed_meta_blocks=0 -O ^64bit -O extents -O ^bigalloc -O ^dir_index -O dir_nlink -O ea_inode -O ^encrypt -O ext_attr -O extra_isize -O flex_bg -O ^huge_file -O ^inline_data -O large_dir -O ^metadata_csum -O meta_bg -O mmp -O quota -O ^resize_inode -O ^sparse_super -O ^uninit_bg -O ^verity -j -J size=1024",
				"-b 1024 -I 256 -E lazy_itable_init=0 -E num_backup_sb=1 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O ^dir_nlink -O ^ea_inode -O ^encrypt -O ext_attr -O ^extra_isize -O flex_bg -O ^huge_file -O ^inline_data -O large_dir -O ^metadata_csum -O meta_bg -O ^mmp -O quota -O ^resize_inode -O ^sparse_super -O uninit_bg -O ^verity",
				"-b 1024 -I 1024 -E lazy_itable_init=0 -E num_backup_sb=1 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O ^dir_nlink -O ^ea_inode -O encrypt -O ext_attr -O ^extra_isize -O flex_bg -O ^huge_file -O inline_data -O large_dir -O ^metadata_csum -O meta_bg -O ^mmp -O quota -O ^resize_inode -O ^sparse_super -O uninit_bg -O ^verity -j -J size=1024",
				"-b 1024 -I 128 -E lazy_itable_init=1 -E num_backup_sb=0 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O dir_nlink -O ea_inode -O ^encrypt -O ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O ^inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O mmp -O ^quota -O resize_inode -O sparse_super -O ^uninit_bg -O ^verity",
				"-b 1024 -I 256 -E lazy_itable_init=1 -E num_backup_sb=0 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O dir_nlink -O ea_inode -O ^encrypt -O ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O mmp -O ^quota -O resize_inode -O sparse_super -O ^uninit_bg -O ^verity",
				"-b 1024 -I 256 -E lazy_itable_init=1 -E num_backup_sb=1 -E packed_meta_blocks=0 -O ^64bit -O ^extents -O ^bigalloc -O dir_index -O ^dir_nlink -O ea_inode -O encrypt -O ^ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O ^mmp -O ^quota -O ^resize_inode -O sparse_super2 -O uninit_bg -O ^verity -j -J size=1024",
				"-b 1024 -I 512 -E lazy_itable_init=1 -E num_backup_sb=1 -E packed_meta_blocks=0 -O ^64bit -O ^extents -O ^bigalloc -O dir_index -O ^dir_nlink -O ea_inode -O encrypt -O ^ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O ^mmp -O ^quota -O ^resize_inode -O sparse_super2 -O uninit_bg -O ^verity",
				"-b 2048 -I 128 -E lazy_itable_init=0 -E num_backup_sb=0 -E packed_meta_blocks=0 -O ^64bit -O extents -O ^bigalloc -O ^dir_index -O dir_nlink -O ea_inode -O ^encrypt -O ext_attr -O extra_isize -O flex_bg -O ^huge_file -O ^inline_data -O large_dir -O ^metadata_csum -O meta_bg -O mmp -O quota -O ^resize_inode -O ^sparse_super -O ^uninit_bg -O ^verity",
				"-b 2048 -I 256 -E lazy_itable_init=0 -E num_backup_sb=1 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O ^dir_nlink -O ^ea_inode -O encrypt -O ext_attr -O ^extra_isize -O flex_bg -O ^huge_file -O ^inline_data -O large_dir -O ^metadata_csum -O meta_bg -O ^mmp -O quota -O ^resize_inode -O ^sparse_super -O uninit_bg -O ^verity -j -J size=1024",
				"-b 2048 -I 1024 -E lazy_itable_init=0 -E num_backup_sb=1 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O ^dir_nlink -O ^ea_inode -O encrypt -O ext_attr -O ^extra_isize -O flex_bg -O ^huge_file -O inline_data -O large_dir -O ^metadata_csum -O meta_bg -O ^mmp -O quota -O ^resize_inode -O ^sparse_super -O uninit_bg -O ^verity",
				"-b 2048 -I 128 -E lazy_itable_init=1 -E num_backup_sb=0 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O dir_nlink -O ea_inode -O ^encrypt -O ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O ^inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O mmp -O ^quota -O resize_inode -O sparse_super -O ^uninit_bg -O ^verity",
				"-b 2048 -I 256 -E lazy_itable_init=1 -E num_backup_sb=0 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O dir_nlink -O ea_inode -O ^encrypt -O ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O mmp -O ^quota -O resize_inode -O sparse_super -O ^uninit_bg -O ^verity -j -J size=1024",
				"-b 2048 -I 256 -E lazy_itable_init=1 -E num_backup_sb=1 -E packed_meta_blocks=0 -O ^64bit -O ^extents -O ^bigalloc -O dir_index -O ^dir_nlink -O ea_inode -O encrypt -O ^ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O ^mmp -O ^quota -O ^resize_inode -O sparse_super2 -O uninit_bg -O ^verity",
				"-b 2048 -I 512 -E lazy_itable_init=1 -E num_backup_sb=1 -E packed_meta_blocks=0 -O ^64bit -O ^extents -O ^bigalloc -O dir_index -O ^dir_nlink -O ea_inode -O ^encrypt -O ^ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O ^mmp -O ^quota -O ^resize_inode -O sparse_super2 -O uninit_bg -O ^verity",
				"-b 4096 -I 128 -E lazy_itable_init=0 -E num_backup_sb=0 -E packed_meta_blocks=0 -O ^64bit -O extents -O ^bigalloc -O ^dir_index -O dir_nlink -O ea_inode -O ^encrypt -O ext_attr -O extra_isize -O flex_bg -O ^huge_file -O ^inline_data -O large_dir -O ^metadata_csum -O meta_bg -O mmp -O quota -O ^resize_inode -O ^sparse_super -O ^uninit_bg -O ^verity -j -J size=1024",
				"-b 4096 -I 256 -E lazy_itable_init=0 -E num_backup_sb=1 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O ^dir_nlink -O ^ea_inode -O encrypt -O ext_attr -O ^extra_isize -O flex_bg -O ^huge_file -O ^inline_data -O large_dir -O ^metadata_csum -O meta_bg -O ^mmp -O quota -O ^resize_inode -O ^sparse_super -O uninit_bg -O verity",
				"-b 4096 -I 1024 -E lazy_itable_init=0 -E num_backup_sb=1 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O ^dir_nlink -O ^ea_inode -O ^encrypt -O ext_attr -O ^extra_isize -O flex_bg -O ^huge_file -O inline_data -O large_dir -O ^metadata_csum -O meta_bg -O ^mmp -O quota -O ^resize_inode -O ^sparse_super -O uninit_bg -O ^verity",
				"-b 4096 -I 128 -E lazy_itable_init=1 -E num_backup_sb=0 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O dir_nlink -O ea_inode -O ^encrypt -O ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O ^inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O mmp -O ^quota -O resize_inode -O sparse_super -O ^uninit_bg -O verity -j -J size=1024",
				"-b 4096 -I 256 -E lazy_itable_init=1 -E num_backup_sb=0 -E packed_meta_blocks=1 -O  64bit -O extents -O bigalloc -O ^dir_index -O dir_nlink -O ea_inode -O ^encrypt -O ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O mmp -O ^quota -O resize_inode -O sparse_super -O ^uninit_bg -O ^verity",
				"-b 4096 -I 256 -E lazy_itable_init=1 -E num_backup_sb=1 -E packed_meta_blocks=0 -O ^64bit -O ^extents -O ^bigalloc -O dir_index -O ^dir_nlink -O ea_inode -O ^encrypt -O ^ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O ^mmp -O ^quota -O ^resize_inode -O sparse_super2 -O uninit_bg -O verity -j -J size=1024",
				"-b 4096 -I 512 -E lazy_itable_init=1 -E num_backup_sb=1 -E packed_meta_blocks=0 -O ^64bit -O ^extents -O ^bigalloc -O dir_index -O ^dir_nlink -O ea_inode -O encrypt -O ^ext_attr -O ^extra_isize -O ^flex_bg -O huge_file -O inline_data -O ^large_dir -O ^metadata_csum -O ^meta_bg -O ^mmp -O ^quota -O ^resize_inode -O sparse_super2 -O uninit_bg -O ^verity",
			},
		},
	},
	{
		Name:      "gfs2",
		MinSize:   16 << 20,
		ReadOnly:  true, // mounting this crashes my host kernel
		MkfsFlags: []string{"-O", "-t", "syz:syz"},
		MkfsFlagCombinations: [][]string{
			{
				// Lots of combinations lead to huge images that don't fit into 4MB encodingexec buffer.
				"-b 1024 -o sunit=1024 -o swidth=1024 -c 1M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 1024 -o sunit=1024 -o swidth=1024 -c 1M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 1024 -o sunit=1024 -o swidth=1024 -c 4M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 1024 -o sunit=1024 -o swidth=1024 -c 4M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 1024 -o sunit=4096 -o swidth=8192 -c 1M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 1024 -o sunit=4096 -o swidth=8192 -c 1M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 1024 -o sunit=4096 -o swidth=8192 -c 4M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 1024 -o sunit=4096 -o swidth=8192 -c 4M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 2048 -o sunit=2048 -o swidth=4096 -c 1M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 2048 -o sunit=2048 -o swidth=4096 -c 1M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 2048 -o sunit=2048 -o swidth=4096 -c 4M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 2048 -o sunit=2048 -o swidth=4096 -c 4M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 2048 -o sunit=4096 -o swidth=4096 -c 1M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 2048 -o sunit=4096 -o swidth=4096 -c 1M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 2048 -o sunit=4096 -o swidth=4096 -c 4M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 2048 -o sunit=4096 -o swidth=4096 -c 4M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 4096 -o sunit=4096 -o swidth=4096 -c 1M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 4096 -o sunit=4096 -o swidth=4096 -c 1M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 4096 -o sunit=4096 -o swidth=4096 -c 1M -j 2 -J 16 -o align=0 -p lock_dlm",
				"-b 4096 -o sunit=4096 -o swidth=4096 -c 1M -j 2 -J 16 -o align=1 -p lock_nolock",
				"-b 4096 -o sunit=4096 -o swidth=4096 -c 4M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 4096 -o sunit=4096 -o swidth=4096 -c 4M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 4096 -o sunit=4096 -o swidth=4096 -c 4M -j 2 -J 16 -o align=0 -p lock_dlm",
				"-b 4096 -o sunit=4096 -o swidth=4096 -c 4M -j 2 -J 16 -o align=1 -p lock_nolock",
				"-b 4096 -o sunit=8192 -o swidth=16384 -c 1M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 4096 -o sunit=8192 -o swidth=16384 -c 1M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 4096 -o sunit=8192 -o swidth=16384 -c 1M -j 2 -J 16 -o align=0 -p lock_dlm",
				"-b 4096 -o sunit=8192 -o swidth=16384 -c 1M -j 2 -J 16 -o align=1 -p lock_nolock",
				"-b 4096 -o sunit=8192 -o swidth=16384 -c 4M -j 1 -J 8 -o align=0 -p lock_dlm",
				"-b 4096 -o sunit=8192 -o swidth=16384 -c 4M -j 1 -J 8 -o align=1 -p lock_nolock",
				"-b 4096 -o sunit=8192 -o swidth=16384 -c 4M -j 2 -J 16 -o align=0 -p lock_dlm",
				"-b 4096 -o sunit=8192 -o swidth=16384 -c 4M -j 2 -J 16 -o align=1 -p lock_nolock",
			},
		},
	},
	{
		Name:     "ocfs2",
		MinSize:  8 << 20,
		ReadOnly: true, // mounting this crashes my host kernel
		MkfsFlagCombinations: [][]string{
			{"-b 512", "-b 4096"},
			{"-C 4K", "-C 16K", "-C 1M"},
			{"-J block32", "-J block64"},
			{"-T mail -N 1 -M local", "-T datafiles -N 2 -M local", "-T vmstore -N 2 -M cluster"},
			{"", "--fs-features backup-super,sparse,unwritten,inline-data,extended-slotmap,metaecc,refcount,xattr,usrquota,grpquota,indexed-dirs,discontig-bg"},
		},
	},
	{
		Name:    "cramfs",
		MinSize: 1 << 10,
		// The file system is read-only and requires a root directory at creation time.
		ReadOnly:  true,
		MkfsFlags: []string{},
		MkfsFlagCombinations: [][]string{
			{"-b 4096", "-b 8192"},
			{"-N big", "-N little"},
		},
		Mkfs: func(image *Image) error {
			_, err := runCmd("mkfs.cramfs", append(image.flags, image.templateDir, image.disk)...)
			return err
		},
	},
	{
		Name:    "romfs",
		MinSize: 1 << 10,
		// The file system is read-only and requires a root directory at creation time.
		ReadOnly: true,
		MkfsFlagCombinations: [][]string{
			{"-a 16", "-a 256"},
		},
		Mkfs: func(image *Image) error {
			_, err := runCmd("genromfs", append(image.flags, "-f", image.disk, "-d", image.templateDir)...)
			return err
		},
	},
	{
		Name:    "erofs",
		MinSize: 1 << 10,
		// The file system is read-only and requires a root directory at creation time.
		ReadOnly:  true,
		MkfsFlags: []string{"-T1000"},
		MkfsFlagCombinations: [][]string{
			{"-z lz4,1", "-z lz4,9", "-z lz4hc,1", "-z lz4hc,9"},
			{"-x 1", "-x 2"},
			{"", "-E legacy-compress"},
		},
		Mkfs: func(image *Image) error {
			_, err := runCmd("mkfs.erofs", append(image.flags, image.disk, image.templateDir)...)
			return err
		},
	},
	{
		Name:    "efs",
		MinSize: 1 << 10,
		// The file system is read-only and requires a root directory at creation time.
		ReadOnly:  true,
		MkfsFlags: []string{"-M", "65536"},
		MkfsFlagCombinations: [][]string{
			{
				"-t ffs -B big    -S 128  -o bsize=4k,version=1,optimization=space",
				"-t ffs -B big    -S 512  -o bsize=8k,version=1,optimization=time",
				"-t ffs -B big    -S 2048 -o bsize=8k,version=1,optimization=space",
				"-t ffs -B little -S 128  -o bsize=4k,version=1,optimization=time",
				"-t ffs -B little -S 512  -o bsize=4k,version=1,optimization=space",
				"-t ffs -B little -S 2048 -o bsize=8k,version=1,optimization=time",
				"-t ffs -B big    -S 128  -o bsize=4k,version=2,optimization=space",
				"-t ffs -B big    -S 512  -o bsize=8k,version=2,optimization=time",
				"-t ffs -B big    -S 2048 -o bsize=8k,version=2,optimization=space",
				"-t ffs -B little -S 128  -o bsize=4k,version=2,optimization=time",
				"-t ffs -B little -S 512  -o bsize=4k,version=2,optimization=space",
				"-t ffs -B little -S 2048 -o bsize=8k,version=2,optimization=time",
				"-t cd9660",
				"-t cd9660 -o rockridge",
			},
		},
		Mkfs: func(image *Image) error {
			_, err := runCmd("makefs", append(image.flags, image.disk, image.templateDir)...)
			return err
		},
	},
	{
		Name:      "udf",
		MinSize:   64 << 10,
		MkfsFlags: []string{"-u", "1234567812345678"},
		MkfsFlagCombinations: [][]string{
			{"-b 512", "-b 1024", "-b 4096"},
			{
				"-m hd -r 1.01",
				"-m hd -r 1.01 --ad=short",
				"-m hd -r 1.50 --ad=long",
				"-m hd -r 2.01",
				"-m hd -r 2.01 --space=unallocbitmap",
				"-m mo -r 1.01",
				"-m mo -r 1.01  --ad=long",
				"-m mo -r 1.50 --space=unalloctable",
				"-m mo -r 1.50 --space=unallocbitmap",
				"-m mo -r 2.01 --noefe --ad=short",
				"-m cdrw -r 1.50",
				"-m cdrw -r 1.50 --space=unalloctable --ad=long",
				"-m cdrw -r 2.01",
				"-m dvdrw -r 1.50 --space=unallocbitmap --ad=short",
				"-m dvdrw -r 2.01 --space=unalloctable --noefe",
				"-m dvdrw -r 2.01",
				"-m dvdram -r 1.50  --ad=long",
				"-m dvdram -r 2.01 ",
				"-m dvdram -r 2.01 --space=unallocbitmap  --ad=long",
			},
		},
	},
	{
		Name:      "jffs2",
		MinSize:   1 << 10,
		ReadOnly:  true,
		MkfsFlags: []string{"--squash", "--faketime", "--with-xattr"},
		MkfsFlagCombinations: [][]string{
			{"--pagesize 4096", "--pagesize 8192"},
			{"--little-endian", "--big-endian"},
			{"--compression-mode=none", "--compression-mode=size"},
		},
		Mkfs: func(image *Image) error {
			_, err := runCmd("mkfs.jffs2", append(image.flags, "-o", image.disk, "--root", image.templateDir)...)
			return err
		},
	},
	{
		Name:    "nilfs2",
		MinSize: 1 << 20,
		MkfsFlagCombinations: [][]string{
			{"-b 1024", "-b 2048", "-b 4096"},
			{"-B 16", "-B 64", "-B 512"},
			{"-O none", "-O block_count"},
		},
	},
	{
		Name:     "squashfs",
		MinSize:  1 << 10,
		ReadOnly: true,
		MkfsFlagCombinations: [][]string{
			{"-comp gzip -b 4k", "-comp lzo -b 16k", "-comp xz -b 1M"},
			{"", "-noI -noX", "-noI -noD -noF -noX"},
			{"-no-fragments", "-always-use-fragments -nopad"},
		},
		Mkfs: func(image *Image) error {
			os.Remove(image.disk)
			_, err := runCmd("mksquashfs", append([]string{image.templateDir, image.disk}, image.flags...)...)
			return err
		},
	},
	{
		Name:      "iso9660",
		MinSize:   1 << 10,
		ReadOnly:  true,
		MkfsFlags: []string{"-abstract", "file1", "-biblio", "file2", "-copyright", "file3", "-publisher", "syzkaller"},
		MkfsFlagCombinations: [][]string{
			{"", "-J", "-J -udf"},
			{"-pad", "-no-pad"},
			{"", "-hfs", "-apple -r"},
		},
		Mkfs: func(image *Image) error {
			_, err := runCmd("genisoimage", append(image.flags, "-o", image.disk, image.templateDir)...)
			return err
		},
	},
}

// Image represents one image we generate for a file system.
type Image struct {
	target      *prog.Target
	fs          FileSystem
	flags       []string // mkfs flags
	index       int      // index within the file system
	size        int      // image size (autodetected starting from fs.MinSize)
	hash        uint32   // crc32 hash of the resulting image to detect duplicates
	disk        string   // disk image file name
	templateDir string   // name of a directory with contents for the file system (shared across all images)
	done        chan error
}

var errShutdown = errors.New("shutdown")

func main() {
	var (
		flagList      = flag.Bool("list", false, "list supported file systems and exit")
		flagVerbose   = flag.Bool("v", false, "print successfully created images")
		flagDebug     = flag.Bool("debug", false, "print lots of debugging output")
		flagPopulate  = flag.String("populate", "", "populate the specified image with files (for internal use)")
		flagKeepImage = flag.Bool("keep", false, "save disk images as .img files")
		flagFS        = flag.String("fs", "", "generate images only for this single filesystem")
	)
	flag.Parse()
	if *flagDebug {
		*flagVerbose = true
	}
	if *flagPopulate != "" {
		if err := populate(*flagPopulate, *flagFS); err != nil {
			tool.Fail(err)
		}
		return
	}
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		tool.Fail(err)
	}
	images, err := generateImages(target, *flagFS, *flagList)
	if err != nil {
		tool.Fail(err)
	}
	if *flagList {
		return
	}
	// Create a single template dir for file systems that need the root dir at creation time.
	templateDir, err := ioutil.TempDir("", "syz-imagegen")
	if err != nil {
		tool.Fail(err)
	}
	defer os.RemoveAll(templateDir)
	if err := populateDir(templateDir); err != nil {
		tool.Fail(err)
	}
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	procs := runtime.NumCPU()
	requests := make(chan *Image, procs)
	go func() {
		for _, image := range images {
			image.templateDir = templateDir
			requests <- image
		}
		close(requests)
	}()
	for p := 0; p < procs; p++ {
		go func() {
			for image := range requests {
				select {
				case <-shutdown:
					image.done <- errShutdown
				default:
					image.done <- image.generate()
				}
			}
		}()
	}
	printResults(images, shutdown, *flagKeepImage, *flagVerbose)
}

func printResults(images []*Image, shutdown chan struct{}, keepImage, verbose bool) {
	good, failed := 0, 0
	hashes := make(map[uint32][]*Image)
	for _, image := range images {
		err := <-image.done
		if image.disk != "" && !keepImage {
			os.Remove(image.disk)
		}
		select {
		case <-shutdown:
			err = errShutdown
		default:
		}
		if err == errShutdown {
			continue
		}
		size := fmt.Sprintf("%vKB", image.size>>10)
		if image.size >= 1<<20 {
			size = fmt.Sprintf("%vMB", image.size>>20)
		}
		res := "ok"
		if err != nil {
			res = fmt.Sprintf("failed:\n\t%v", err)
		}
		if verbose || err != nil {
			fmt.Printf("#%02v: mkfs.%v[%5v] %v: %v\n", image.index, image.fs.Name, size, image.flags, res)
		}
		if err != nil {
			failed++
			continue
		}
		hashes[image.hash] = append(hashes[image.hash], image)
		good++
	}
	fmt.Printf("generated images: %v/%v\n", good, len(images))
	for _, image := range images {
		group := hashes[image.hash]
		if len(group) <= 1 {
			continue
		}
		delete(hashes, image.hash)
		fmt.Printf("equal images:\n")
		for _, image := range group {
			fmt.Printf("\tmkfs.%v %v\n", image.fs.Name, image.flags)
		}
	}
	if failed != 0 {
		os.Exit(1)
	}
}

func generateImages(target *prog.Target, flagFS string, list bool) ([]*Image, error) {
	var images []*Image
	for _, fs := range fileSystems {
		if flagFS != "" && flagFS != fs.Name {
			continue
		}
		index := 0
		enumerateFlags(target, &images, &index, fs, fs.MkfsFlags, 0)
		if list {
			fmt.Printf("%v [%v images]\n", fs.Name, index)
			continue
		}
		files, err := filepath.Glob(filepath.Join("sys", targets.Linux, "test", "syz_mount_image_"+fs.Name+"_*"))
		if err != nil {
			return nil, fmt.Errorf("error reading output dir: %v", err)
		}
		for _, file := range files {
			if err := os.Remove(file); err != nil {
				return nil, fmt.Errorf("error removing output file: %v", err)
			}
		}
	}
	return images, nil
}

func enumerateFlags(target *prog.Target, images *[]*Image, index *int, fs FileSystem, flags []string, flagsIndex int) {
	if flagsIndex == len(fs.MkfsFlagCombinations) {
		*images = append(*images, &Image{
			target: target,
			fs:     fs,
			flags:  append([]string{}, flags...),
			index:  *index,
			done:   make(chan error, 1),
		})
		*index++
		return
	}
	for _, flag := range fs.MkfsFlagCombinations[flagsIndex] {
		flags1 := flags
		for _, f := range strings.Split(flag, " ") {
			if f != "" {
				flags1 = append(flags1, f)
			}
		}
		enumerateFlags(target, images, index, fs, flags1, flagsIndex+1)
	}
}

func (image *Image) generate() error {
	var err error
	for image.size = image.fs.MinSize; image.size <= 128<<20; image.size *= 2 {
		if err = image.generateSize(); err == nil {
			return nil
		}
	}
	return err
}

func (image *Image) generateSize() error {
	outFile := filepath.Join("sys", targets.Linux, "test",
		fmt.Sprintf("syz_mount_image_%v_%v", image.fs.Name, image.index))
	image.disk = outFile + ".img"
	f, err := os.Create(image.disk)
	if err != nil {
		return err
	}
	f.Close()
	if err := os.Truncate(image.disk, int64(image.size)); err != nil {
		return err
	}
	if image.fs.Mkfs == nil {
		if _, err := runCmd("mkfs."+image.fs.Name, append(image.flags, image.disk)...); err != nil {
			return err
		}
	} else {
		if err := image.fs.Mkfs(image); err != nil {
			return err
		}
	}
	if !image.fs.ReadOnly {
		// This does not work with runCmd -- sudo does not show password prompt on console.
		cmd := exec.Command("sudo", os.Args[0], "-populate", image.disk, "-fs", image.fs.Name)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("image population failed: %v\n%s", err, out)
		}
	}
	data, err := ioutil.ReadFile(image.disk)
	if err != nil {
		return err
	}
	image.hash = crc32.ChecksumIEEE(data)
	out, err := writeImage(image.fs, data)
	if err != nil {
		return err
	}
	p, err := image.target.Deserialize(out, prog.Strict)
	if err != nil {
		return fmt.Errorf("failed to deserialize resulting program: %v", err)
	}
	exec := make([]byte, prog.ExecBufferSize)
	if _, err := p.SerializeForExec(exec); err != nil {
		return fmt.Errorf("failed to serialize for execution: %v", err)
	}
	return osutil.WriteFile(outFile, out)
}

// Runs under sudo in a subprocess.
func populate(disk, fs string) error {
	output, err := runCmd("losetup", "-f", "--show", "-P", disk)
	if err != nil {
		return err
	}
	loop := strings.TrimSpace(string(output))
	defer runCmd("losetup", "-d", loop)

	dir, err := ioutil.TempDir("", "syz-imagegen")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if _, err := runCmd("mount", "-t", fs, loop, dir); err != nil {
		return fmt.Errorf("%v\n%s", err, output)
	}
	defer runCmd("umount", dir)
	return populateDir(dir)
}

func populateDir(dir string) error {
	zeros := func(size int) []byte {
		return make([]byte, size)
	}
	nonzeros := func(size int) []byte {
		const fill = "syzkaller"
		return bytes.Repeat([]byte(fill), size/len(fill)+1)[:size]
	}
	if err := os.Mkdir(filepath.Join(dir, "file0"), 0777); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(dir, "file0", "file0"), nonzeros(1050), 0777); err != nil {
		return err
	}
	os.Symlink(filepath.Join(dir, "file0", "file0"), filepath.Join(dir, "file0", "file1"))
	if err := ioutil.WriteFile(filepath.Join(dir, "file1"), nonzeros(10), 0777); err != nil {
		return err
	}
	// Note: some errors are not checked because some file systems don't have support for links/attrs.
	// TODO: does it make sense to create other attribute types (system./trusted./security./btrfs.)?
	syscall.Setxattr(filepath.Join(dir, "file1"), "user.xattr1", []byte("xattr1"), 0)
	syscall.Setxattr(filepath.Join(dir, "file1"), "user.xattr2", []byte("xattr2"), 0)
	if err := ioutil.WriteFile(filepath.Join(dir, "file2"), zeros(9000), 0777); err != nil {
		return err
	}
	os.Link(filepath.Join(dir, "file2"), filepath.Join(dir, "file3"))
	// f2fs considers .cold extension specially.
	if err := ioutil.WriteFile(filepath.Join(dir, "file.cold"), nonzeros(100), 0777); err != nil {
		return err
	}
	return nil
}

func runCmd(cmd string, args ...string) ([]byte, error) {
	return osutil.RunCmd(10*time.Minute, "", cmd, args...)
}

func writeImage(fs FileSystem, data []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "# Code generated by tools/syz-imagegen. DO NOT EDIT.\n")
	fmt.Fprintf(buf, "# requires: manual\n\n")
	segs := calculateSegments(data)
	fmt.Fprintf(buf, `syz_mount_image$%v(&(0x7f0000000000)='%v\x00', &(0x7f0000000100)='./file0\x00',`+
		` 0x%x, 0x%x, &(0x7f0000000200)=[`,
		fs.Name, fs.Name, len(data), len(segs))
	addr := 0x7f0000010000
	for i, seg := range segs {
		if i != 0 {
			fmt.Fprintf(buf, ", ")
		}
		fmt.Fprintf(buf, `{&(0x%x)="%v", 0x%x, 0x%x}`,
			addr, hex.EncodeToString(seg.data), len(seg.data), seg.offset)
		addr += len(seg.data)
	}
	fmt.Fprintf(buf, "], 0x0, &(0x%x))\n", addr)
	return buf.Bytes(), nil
}

type Segment struct {
	offset int
	data   []byte
}

func calculateSegments(data []byte) []Segment {
	const (
		skip  = 32 // min zero bytes to skip
		align = 32 // non-zero block alignment
	)
	data0 := data
	zeros := make([]byte, skip+align)
	var segs []Segment
	offset := 0
	for len(data) != 0 {
		pos := bytes.Index(data, zeros)
		if pos == -1 {
			segs = append(segs, Segment{offset, data})
			break
		}
		pos = (pos + align - 1) & ^(align - 1)
		if pos != 0 {
			segs = append(segs, Segment{offset, data[:pos]})
		}
		for pos < len(data) && data[pos] == 0 {
			pos++
		}
		pos = pos & ^(align - 1)
		offset += pos
		data = data[pos:]
	}
	if false {
		// self-test.
		restored := make([]byte, len(data0))
		for _, seg := range segs {
			copy(restored[seg.offset:], seg.data)
		}
		if !bytes.Equal(data0, restored) {
			panic("restored data differs!")
		}
	}
	return segs
}

// TODO: also generate syz_read_part_table tests:
//	fmt.Printf(`syz_read_part_table(0x%x, 0x%x, &(0x7f0000000200)=[`,
//		len(data0), len(segs))
//	addr := 0x7f0000010000
//	for i, seg := range segs {
//		if i != 0 {
//			fmt.Printf(", ")
//		}
//		fmt.Printf(`{&(0x%x)="%v", 0x%x, 0x%x}`,
//			addr, hex.EncodeToString(seg.data), len(seg.data), seg.offset)
//		addr = (addr + len(seg.data) + 0xff) & ^0xff
//	}
//	fmt.Printf("])\n")
