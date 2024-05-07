// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

type customRules struct {
	// The mapping between a Linux subsystem name and its system calls.
	subsystemCalls map[string][]string
	// These emails do not represent separate subsystems, even though they seem to
	// per all criteria we have.
	notSubsystemEmails map[string]struct{}
	// These subsystems need to be extracted even without mailing lists.
	// Key is the subsystem name, value is the list of raw names in MAINTAINERS.
	extraSubsystems map[string][]string
	// For these subsystems we do not generate monthly reminders.
	noReminders map[string]struct{}
	// We don't want to tag these subsystems in the reports of its sub-subsystem bugs.
	noIndirectCc map[string]struct{}
	// Extra child->[]parent links (on top of the inferred ones).
	addParents map[string][]string
}

var (
	linuxSubsystemRules = &customRules{
		subsystemCalls: map[string][]string{
			"adfs":      {"syz_mount_image$adfs"},
			"affs":      {"syz_mount_image$affs"},
			"bcachefs":  {"syz_mount_image$bcachefs"},
			"befs":      {"syz_mount_image$befs"},
			"bfs":       {"syz_mount_image$bfs"},
			"bluetooth": {"syz_emit_vhci"},
			"btrfs":     {"syz_mount_image$btrfs"},
			"cramfs":    {"syz_mount_image$cramfs"},
			"efs":       {"syz_mount_image$efs"},
			"erofs":     {"syz_mount_image$erofs"},
			"ext4":      {"syz_mount_image$ext4"},
			"f2fs":      {"syz_mount_image$f2fs"},
			"fat": {
				"syz_mount_image$msdos",
				"syz_mount_image$vfat",
				"syz_mount_image$exfat",
			},
			"fuse":     {"syz_fuse_handle_req"},
			"gfs2":     {"syz_mount_image$gfs2", "syz_mount_image$gfs2meta"},
			"hfs":      {"syz_mount_image$hfs", "syz_mount_image$hfsplus"},
			"hpfs":     {"syz_mount_image$hpfs"},
			"input":    {"syz_usb_connect$hid"},
			"io-uring": {"syz_io_uring_setup"},
			"isofs":    {"syz_mount_image$iso9660"},
			"jffs2":    {"syz_mount_image$jffs2"},
			"jfs":      {"syz_mount_image$jfs"},
			"kvm":      {"syz_kvm_setup_cpu"},
			"minix":    {"syz_mount_image$minix"},
			"nilfs":    {"syz_mount_image$nilfs2"},
			"ntfs3":    {"syz_mount_image$ntfs", "syz_mount_image$ntfs3"},
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
			"usb": {
				"syz_usb_connect",
				"syz_usb_connect$hid",
				"syz_usb_connect$printer",
				"syz_usb_connect$cdc_ecm",
				"syz_usb_connect$cdc_ncm",
				"syz_usb_connect$uac1",
			},
			"vxfs":     {"syz_mount_image$vxfs"},
			"wireless": {"syz_80211_join_ibss", "syz_80211_inject_frame"},
			"xfs":      {"syz_mount_image$xfs"},
			"zonefs":   {"syz_mount_image$zonefs"},
		},
		notSubsystemEmails: map[string]struct{}{
			"linaro-mm-sig@lists.linaro.org":   {},
			"samba-technical@lists.samba.org":  {},
			"storagedev@microchip.com":         {},
			"coreteam@netfilter.org":           {},
			"SHA-cyfmac-dev-list@infineon.com": {},
		},
		extraSubsystems: map[string][]string{
			"bfs":    {"BFS FILE SYSTEM"},
			"exfat":  {"EXFAT FILE SYSTEM", "VFAT/FAT/MSDOS FILESYSTEM"},
			"fuse":   {"FUSE: FILESYSTEM IN USERSPACE"},
			"hfs":    {"HFS FILESYSTEM", "HFSPLUS FILESYSTEM"},
			"isofs":  {"ISOFS FILESYSTEM"},
			"kernfs": {"KERNFS"},
			"udf":    {"UDF FILESYSTEM"},
			"nfc":    {"NFC SUBSYSTEM"},
			"iomap":  {"FILESYSTEMS [IOMAP]"},
			"xfs":    {"XFS FILESYSTEM"},
			"jffs2":  {"JOURNALLING FLASH FILE SYSTEM V2 (JFFS2)"},
		},
		noReminders: map[string]struct{}{
			// Many misclassified bugs end up in `kernel`, so there's no sense
			// in generating monthly reports for it.
			"kernel": {},
		},
		addParents: map[string][]string{
			// By MAINTAINERS, wireless is somewhat separate, but it's better to keep it as a net child.
			"wireless": {"net"},
		},
		noIndirectCc: map[string]struct{}{
			"fs": {},
		},
	}
)
