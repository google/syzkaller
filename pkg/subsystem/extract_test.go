// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"sort"
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestSimpleLinuxExtract(t *testing.T) {
	se := MakeLinuxSubsystemExtractor()

	ret := se.Extract(&Crash{
		OS: targets.Linux,
		GuiltyFiles: []string{
			"fs/ext4/abc.c",
		},
	})
	assert.Empty(t, ret, "the test should have found 0 subsystems")

	ret = se.Extract(&Crash{
		OS: targets.Linux,
		GuiltyFiles: []string{
			"fs/ext4/abc.c",
			"fs/def.c",
		},
	})
	assert.Exactly(t, ret, []string{"vfs"}, "the test should have only found vfs")
}

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
