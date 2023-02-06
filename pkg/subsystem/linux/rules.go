// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

type customRules struct {
	// The mapping between a Linux subsystem name and its system calls.
	subsystemCalls map[string][]string
	// These emails do not represent separate subsystems, even though they seem to
	// per all criteria we have.
	notSubsystemEmails map[string]struct{}
}

var (
	linuxSubsystemRules = &customRules{
		subsystemCalls: map[string][]string{
			"adfs":     {"syz_mount_image$adfs"},
			"affs":     {"syz_mount_image$affs"},
			"befs":     {"syz_mount_image$befs"},
			"bfs":      {"syz_mount_image$bfs"},
			"btrfs":    {"syz_mount_image$btrfs"},
			"cramfs":   {"syz_mount_image$cramfs"},
			"efs":      {"syz_mount_image$efs"},
			"erofs":    {"syz_mount_image$erofs"},
			"exfat":    {"syz_mount_image$exfat"},
			"ext4":     {"syz_mount_image$ext4"},
			"f2fs":     {"syz_mount_image$f2fs"},
			"fat":      {"syz_mount_image$msdos", "syz_mount_image$vfat"},
			"gfs2":     {"syz_mount_image$gfs2", "syz_mount_image$gfs2meta"},
			"hfs":      {"syz_mount_image$hfs"},
			"hfsplus":  {"syz_mount_image$hfsplus"},
			"hpfs":     {"syz_mount_image$hpfs"},
			"iso9660":  {"syz_mount_image$iso9660"},
			"jffs2":    {"syz_mount_image$jffs2"},
			"jfs":      {"syz_mount_image$jfs"},
			"minix":    {"syz_mount_image$minix"},
			"nilfs2":   {"syz_mount_image$nilfs2"},
			"ntfs":     {"syz_mount_image$ntfs"},
			"ntfs3":    {"syz_mount_image$ntfs3"},
			"ocfs2":    {"syz_mount_image$ocfs2"},
			"omfs":     {"syz_mount_image$omfs"},
			"qnx4":     {"syz_mount_image$qnx4"},
			"qnx6":     {"syz_mount_image$qnx6"},
			"reiserfs": {"syz_mount_image$reiserfs"},
			"romfs":    {"syz_mount_image$romfs"},
			"squashfs": {"syz_mount_image$squashfs"},
			"sysv":     {"syz_mount_image$sysv"},
			"tmpfs":    {"syz_mount_image$tmpfs"},
			"ubifs":    {"syz_mount_image$ubifs"},
			"udf":      {"syz_mount_image$udf"},
			"ufs":      {"syz_mount_image$ufs"},
			"vxfs":     {"syz_mount_image$vxfs"},
			"xfs":      {"syz_mount_image$xfs"},
			"zonefs":   {"syz_mount_image$zonefs"},
		},
		notSubsystemEmails: map[string]struct{}{
			"linaro-mm-sig@lists.linaro.org":  {},
			"samba-technical@lists.samba.org": {},
			"storagedev@microchip.com":        {},
		},
	}
)
