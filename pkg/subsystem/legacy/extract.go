// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package legacy

import (
	"regexp"
	"sync"

	"github.com/google/syzkaller/prog"
)

type SubsystemExtractor struct {
	pathToSubsystems func(path string) []string
	callToSubsystems func(call string) []string
}

// Crash contains the subset of Crash fields relevant for subsystem extraction.
type Crash struct {
	OS          string
	GuiltyFiles []string
	SyzRepro    string
}

func MakeLinuxSubsystemExtractor() *SubsystemExtractor {
	return &SubsystemExtractor{
		pathToSubsystems: linuxPathToSubsystems,
		callToSubsystems: linuxCallToSubsystems,
	}
}

func (se *SubsystemExtractor) Extract(crash *Crash) []string {
	retMap := map[string]bool{}
	// Currently we only have the dumbest possible implementation of subsystem detection.
	if se.pathToSubsystems != nil {
		for _, path := range crash.GuiltyFiles {
			for _, value := range se.pathToSubsystems(path) {
				retMap[value] = true
			}
		}
	}
	if se.callToSubsystems != nil {
		callSet, _, _ := prog.CallSet([]byte(crash.SyzRepro))
		for call := range callSet {
			for _, subsystem := range se.callToSubsystems(call) {
				retMap[subsystem] = true
			}
		}
	}
	retSlice := []string{}
	for name := range retMap {
		retSlice = append(retSlice, name)
	}
	return retSlice
}

func linuxPathToSubsystems(path string) []string {
	ret := []string{}
	if vfsPathRegexp.MatchString(path) {
		ret = append(ret, "vfs")
	}
	linuxSubsystemsOnce.Do(func() {
		for name, info := range linuxSubsystems {
			linuxSubsystemRegexps[name] = regexp.MustCompile("^/?" + info.path + ".*")
		}
	})
	for name, pattern := range linuxSubsystemRegexps {
		if pattern.MatchString(path) {
			ret = append(ret, name)
		}
	}
	return ret
}

var (
	linuxSubsystemsOnce   sync.Once
	linuxSubsystemRegexps = map[string]*regexp.Regexp{}
)

func linuxCallToSubsystems(call string) []string {
	name := linuxCallToSubsystemsMap[call]
	if name != "" {
		return []string{name}
	}
	return nil
}

var linuxCallToSubsystemsMap = map[string]string{
	"syz_mount_image$adfs":     "adfs",
	"syz_mount_image$affs":     "affs",
	"syz_mount_image$befs":     "befs",
	"syz_mount_image$bfs":      "bfs",
	"syz_mount_image$btrfs":    "btrfs",
	"syz_mount_image$cramfs":   "cramfs",
	"syz_mount_image$efs":      "efs",
	"syz_mount_image$erofs":    "erofs",
	"syz_mount_image$exfat":    "exfat",
	"syz_mount_image$ext4":     "ext4",
	"syz_mount_image$f2fs":     "f2fs",
	"syz_mount_image$gfs2":     "gfs2",
	"syz_mount_image$gfs2meta": "gfs2",
	"syz_mount_image$hfs":      "hfs",
	"syz_mount_image$hfsplus":  "hfsplus",
	"syz_mount_image$hpfs":     "hpfs",
	"syz_mount_image$iso9660":  "iso9660",
	"syz_mount_image$jffs2":    "jffs2",
	"syz_mount_image$jfs":      "jfs",
	"syz_mount_image$minix":    "minix",
	"syz_mount_image$msdos":    "fat",
	"syz_mount_image$nilfs2":   "nilfs2",
	"syz_mount_image$ntfs":     "ntfs",
	"syz_mount_image$ntfs3":    "ntfs3",
	"syz_mount_image$ocfs2":    "ocfs2",
	"syz_mount_image$omfs":     "omfs",
	"syz_mount_image$qnx4":     "qnx4",
	"syz_mount_image$qnx6":     "qnx6",
	"syz_mount_image$reiserfs": "reiserfs",
	"syz_mount_image$romfs":    "romfs",
	"syz_mount_image$squashfs": "squashfs",
	"syz_mount_image$sysv":     "sysv",
	"syz_mount_image$tmpfs":    "tmpfs",
	"syz_mount_image$ubifs":    "ubifs",
	"syz_mount_image$udf":      "udf",
	"syz_mount_image$ufs":      "ufs",
	"syz_mount_image$v7":       "v7",
	"syz_mount_image$vfat":     "fat",
	"syz_mount_image$vxfs":     "vxfs",
	"syz_mount_image$xfs":      "xfs",
	"syz_mount_image$zonefs":   "zonefs",
}

var (
	vfsPathRegexp = regexp.MustCompile(`^fs/[^/]+\.c`)
)
