// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package legacy

import (
	"sort"
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestProgCallRules(t *testing.T) {
	se := &SubsystemExtractor{
		pathToSubsystems: linuxPathToSubsystems,
		callToSubsystems: func(call string) []string {
			ret := map[string][]string{
				// Intentionally add some that are not present in the test below.
				"test":               {"test"},
				"syz_io_uring_setup": {"io_uring"},
				"ioctl$TIOCSETD":     {"tty_ioctls", "tty"},
				// Some calls are also omitted to verify that the code works fine this way.
			}
			return ret[call]
		},
	}

	ret := se.Extract(&Crash{
		OS: targets.Linux,
		GuiltyFiles: []string{
			"mm/page-writeback.c",
		},
		// nolint: lll
		SyzRepro: `# https://syzkaller.appspot.com/bug?id=708185e841adf6ca28fc50b126fdf9825fd8ae43
# See https://goo.gl/kgGztJ for information about syzkaller reproducers.
#{"repeat":true,"procs":1,"slowdown":1,"sandbox":"","close_fds":false}
r0 = syz_io_uring_setup(0x3ee4, &(0x7f0000000240), &(0x7f0000002000/0x2000)=nil, &(0x7f0000ffd000/0x3000)=nil, &(0x7f0000000100)=<r1=>0x0, &(0x7f0000000140)=<r2=>0x0)
socket$inet_udplite(0x2, 0x2, 0x88)
r3 = openat$ptmx(0xffffffffffffff9c, &(0x7f0000000040), 0x8a04, 0x0)
syz_io_uring_submit(r1, r2, &(0x7f0000000000)=@IORING_OP_READ=@pass_buffer={0x16, 0x0, 0x0, @fd_index=0x5, 0x0, 0x0}, 0x0)
ioctl$TIOCSETD(r3, 0x5423, &(0x7f0000000580)=0x3)
io_uring_enter(r0, 0x2ff, 0x0, 0x0, 0x0, 0x0)`,
	})
	sort.Strings(ret)
	assert.Exactlyf(t, ret, []string{"io_uring", "tty", "tty_ioctls"},
		"invalid resulting subsystems: %s", ret)
}

func TestFsSubsystemExtraction(t *testing.T) {
	extractor := MakeLinuxSubsystemExtractor()

	tests := []struct {
		guilty     string
		prog       string
		subsystems []string
	}{
		{
			guilty:     "fs/abc.c",
			subsystems: []string{"vfs"},
		},
		{
			guilty: "fs/nilfs2/dat.c",
			// nolint: lll
			prog: `syz_mount_image$nilfs2(&(0x7f0000000000), &(0x7f0000000100)='./file0\x00', 0x100000, 0x3b, &(0x7f0000000200)=[{&(0x7f0000011240)="02", 0x1}, {&(0x7f0000012a40)="03000000", 0x4, 0x1}], 0x0, &(0x7f00000131c0), 0x1)
openat$incfs(0xffffffffffffff9c, &(0x7f0000000000)='.pending_reads\x00', 0x4040, 0x0)`,
			subsystems: []string{"nilfs2"},
		},
		{
			guilty: "fs/namei.c",
			// nolint: lll
			prog: `syz_mount_image$ntfs3(&(0x7f0000000240), &(0x7f000001f3c0)='./file0\x00', 0xc40, &(0x7f00000005c0)=ANY=[@ANYBLOB="0032"], 0x3, 0x1f398, &(0x7f000003e7c0)="111")
r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
mkdirat(r0, &(0x7f0000000180)='./bus\x00', 0x0)
mkdirat(r0, &(0x7f0000000280)='./bus/file0\x00', 0x0)
renameat2(r0, &(0x7f00000004c0)='./file0\x00', r0, &(0x7f0000000500)='./bus/file0/file0\x00', 0x0)`,
			subsystems: []string{"ntfs3", "vfs"},
		},
		{
			guilty: "fs/ext4/file.c",
			// nolint: lll
			prog: `syz_mount_image$ntfs3(&(0x7f0000000240), &(0x7f000001f3c0)='./file0\x00', 0xc40, &(0x7f00000005c0)=ANY=[@ANYBLOB="0032"], 0x3, 0x1f398, &(0x7f000003e7c0)="111")
r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
mkdirat(r0, &(0x7f0000000180)='./bus\x00', 0x0)
mkdirat(r0, &(0x7f0000000280)='./bus/file0\x00', 0x0)
renameat2(r0, &(0x7f00000004c0)='./file0\x00', r0, &(0x7f0000000500)='./bus/file0/file0\x00', 0x0)`,
			subsystems: []string{"ntfs3", "ext4"},
		},
		{
			guilty:     "fs/gfs2/ops_fstype.c",
			subsystems: []string{"gfs2"},
		},
		{
			guilty:     "net/mac80211/main.c",
			subsystems: []string{},
		},
	}

	for i, test := range tests {
		ret := extractor.Extract(&Crash{
			OS:          targets.Linux,
			GuiltyFiles: []string{test.guilty},
			SyzRepro:    test.prog,
		})
		sort.Strings(ret)
		sort.Strings(test.subsystems)
		assert.Exactlyf(t, ret, test.subsystems, "#%d: invalid resulting subsystems", i)
	}
}
