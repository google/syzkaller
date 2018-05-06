// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package freebsd

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/freebsd/gen"
	"github.com/google/syzkaller/sys/targets"
)

func init() {
	prog.RegisterTarget(gen.Target_amd64, initTarget)
}

func initTarget(target *prog.Target) {
	arch := &arch{
		MAP_FIXED: target.ConstMap["MAP_FIXED"],
		S_IFREG:   target.ConstMap["S_IFREG"],
		S_IFCHR:   target.ConstMap["S_IFCHR"],
		S_IFBLK:   target.ConstMap["S_IFBLK"],
		S_IFIFO:   target.ConstMap["S_IFIFO"],
		S_IFSOCK:  target.ConstMap["S_IFSOCK"],
	}

	target.MakeMmap = targets.MakePosixMmap(target)
	target.SanitizeCall = arch.sanitizeCall
}

type arch struct {
	MAP_FIXED uint64
	S_IFREG   uint64
	S_IFCHR   uint64
	S_IFBLK   uint64
	S_IFIFO   uint64
	S_IFSOCK  uint64
}

func (arch *arch) sanitizeCall(c *prog.Call) {
	switch c.Meta.CallName {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		c.Args[3].(*prog.ConstArg).Val |= arch.MAP_FIXED
	case "mknod", "mknodat":
		pos := 1
		if c.Meta.CallName == "mknodat" {
			pos = 2
		}
		mode := c.Args[pos].(*prog.ConstArg)
		dev := c.Args[pos+1].(*prog.ConstArg)
		// Char and block devices read/write io ports, kernel memory and do other nasty things.
		// TODO: not required if executor drops privileges.
		switch mode.Val & (arch.S_IFREG | arch.S_IFCHR | arch.S_IFBLK | arch.S_IFIFO | arch.S_IFSOCK) {
		case arch.S_IFREG, arch.S_IFIFO, arch.S_IFSOCK:
		case arch.S_IFBLK:
			// TODO(dvyukov): mknod dev argument is uint32,
			// but prog arguments contain not-truncated uint64 values,
			// so we can mistakenly assume that this is not loop, when it actually is.
			// This is not very harmful, but need to verify other arguments in this function.
			if dev.Val>>8 == 7 {
				break // loop
			}
			mode.Val &^= arch.S_IFBLK
			mode.Val |= arch.S_IFREG
		case arch.S_IFCHR:
			mode.Val &^= arch.S_IFCHR
			mode.Val |= arch.S_IFREG
		}
	case "exit":
		code := c.Args[0].(*prog.ConstArg)
		// These codes are reserved by executor.
		if code.Val%128 == 67 || code.Val%128 == 68 {
			code.Val = 1
		}
	}
}
