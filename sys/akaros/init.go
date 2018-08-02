// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package akaros

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type arch struct {
	unix *targets.UnixSanitizer
}

func InitTarget(target *prog.Target) {
	arch := &arch{
		unix: targets.MakeUnixSanitizer(target),
	}
	target.MakeMmap = targets.MakePosixMmap(target)
	target.SanitizeCall = arch.sanitizeCall
}

func (arch *arch) sanitizeCall(c *prog.Call) {
	arch.unix.SanitizeCall(c)
	switch c.Meta.CallName {
	case "provision":
		if pid, ok := c.Args[0].(*prog.ConstArg); ok && uint32(pid.Val) == ^uint32(0) {
			// pid -1 causes some debugging splat on console.
			pid.Val = 0
		}
	}
}
