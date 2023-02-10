// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubsystemExtractor(t *testing.T) {
	ioUring := &Subsystem{
		Name: "io_uring",
		PathRules: []PathRule{
			{
				IncludeRegexp: `io_uring/.*`,
			},
		},
		Syscalls: []string{"syz_io_uring_setup"},
	}
	security := &Subsystem{
		Name: "security",
		PathRules: []PathRule{
			{
				IncludeRegexp: `security/.*`,
				ExcludeRegexp: `security/selinux/.*`,
			},
			{
				IncludeRegexp: `net/ipv6/calipso\.c`,
			},
		},
	}
	net := &Subsystem{
		Name: "net",
		PathRules: []PathRule{
			{
				IncludeRegexp: `net/.*`,
			},
		},
	}
	obj := makeRawExtractor([]*Subsystem{ioUring, security, net})

	// Verify path matching.
	assert.ElementsMatch(t, obj.FromPath(`io_uring/file.c`), []*Subsystem{ioUring})
	assert.ElementsMatch(t, obj.FromPath(`security/file.c`), []*Subsystem{security})
	assert.ElementsMatch(t, obj.FromPath(`security/selinux/file.c`), []*Subsystem{})
	assert.ElementsMatch(t, obj.FromPath(`net/ipv6/calipso.c`), []*Subsystem{net, security})

	// Verify prog matching.
	// nolint: lll
	assert.ElementsMatch(t, obj.FromProg([]byte(
		`# https://syzkaller.appspot.com/bug?id=708185e841adf6ca28fc50b126fdf9825fd8ae43
# See https://goo.gl/kgGztJ for information about syzkaller reproducers.
#{"repeat":true,"procs":1,"slowdown":1,"sandbox":"","close_fds":false}
r0 = syz_io_uring_setup(0x3ee4, &(0x7f0000000240), &(0x7f0000002000/0x2000)=nil, &(0x7f0000ffd000/0x3000)=nil, &(0x7f0000000100)=<r1=>0x0, &(0x7f0000000140)=<r2=>0x0)
socket$inet_udplite(0x2, 0x2, 0x88)
r3 = openat$ptmx(0xffffffffffffff9c, &(0x7f0000000040), 0x8a04, 0x0)
syz_io_uring_submit(r1, r2, &(0x7f0000000000)=@IORING_OP_READ=@pass_buffer={0x16, 0x0, 0x0, @fd_index=0x5, 0x0, 0x0}, 0x0)
ioctl$TIOCSETD(r3, 0x5423, &(0x7f0000000580)=0x3)
io_uring_enter(r0, 0x2ff, 0x0, 0x0, 0x0, 0x0)`)),
		[]*Subsystem{ioUring})
	// nolint: lll
	assert.ElementsMatch(t, obj.FromProg([]byte(
		`syz_mount_image$nilfs2(&(0x7f0000000000), &(0x7f0000000100)='./file0\x00', 0x100000, 0x3b, &(0x7f0000000200)=[{&(0x7f0000011240)="02", 0x1}, {&(0x7f0000012a40)="03000000", 0x4, 0x1}], 0x0, &(0x7f00000131c0), 0x1)
openat$incfs(0xffffffffffffff9c, &(0x7f0000000000)='.pending_reads\x00', 0x4040, 0x0)`)),
		[]*Subsystem{})
}
