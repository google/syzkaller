// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package openbsd

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
	arch := &arch{
		unix: targets.MakeUnixSanitizer(target),
	}

	target.MakeMmap = targets.MakePosixMmap(target)
	target.SanitizeCall = arch.SanitizeCall
}

type arch struct {
	unix *targets.UnixSanitizer
}

func (arch *arch) SanitizeCall(c *prog.Call) {
	arch.unix.SanitizeCall(c)

	// Prevent vnodes of type VBAD from being created. Such vnodes will
	// likely trigger assertion errors by the kernel.
	pos := 1
	switch c.Meta.CallName {
	case "mknodat":
		pos = 2
		fallthrough
	case "mknod":
		mode := c.Args[pos].(*prog.ConstArg)
		if (mode.Val & arch.unix.S_IFMT) != arch.unix.S_IFMT {
			return
		}
		saneMode := mode.Val & ^arch.unix.S_IFMT
		switch {
		case (mode.Val & arch.unix.S_IFCHR) == arch.unix.S_IFCHR:
			mode.Val = saneMode | arch.unix.S_IFCHR
		case (mode.Val & arch.unix.S_IFBLK) == arch.unix.S_IFBLK:
			mode.Val = saneMode | arch.unix.S_IFBLK
		case (mode.Val & arch.unix.S_IFIFO) == arch.unix.S_IFIFO:
			mode.Val = saneMode | arch.unix.S_IFIFO
		}
	}
}
