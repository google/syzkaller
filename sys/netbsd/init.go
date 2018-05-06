// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package netbsd

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/netbsd/gen"
	"github.com/google/syzkaller/sys/targets"
)

func init() {
	prog.RegisterTarget(gen.Target_amd64, initTarget)
}

func initTarget(target *prog.Target) {
	arch := &arch{
		MAP_FIXED: target.ConstMap["MAP_FIXED"],
	}

	target.MakeMmap = targets.MakePosixMmap(target)
	target.SanitizeCall = arch.sanitizeCall
}

type arch struct {
	MAP_FIXED uint64
}

func (arch *arch) sanitizeCall(c *prog.Call) {
	switch c.Meta.CallName {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		c.Args[3].(*prog.ConstArg).Val |= arch.MAP_FIXED
	case "mknod", "mknodat":
		break
	case "exit":
		code := c.Args[0].(*prog.ConstArg)
		// These codes are reserved by executor.
		if code.Val%128 == 67 || code.Val%128 == 68 {
			code.Val = 1
		}
	}
}
