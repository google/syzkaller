// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package akaros

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type arch struct {
	MAP_FIXED uint64
}

func InitTarget(target *prog.Target) {
	arch := &arch{
		MAP_FIXED: target.GetConst("MAP_FIXED"),
	}
	target.MakeDataMmap = targets.MakePosixMmap(target, true, false)
	target.Neutralize = arch.Neutralize
}

func (arch *arch) Neutralize(c *prog.Call) {
	switch c.Meta.CallName {
	case "mmap":
		c.Args[3].(*prog.ConstArg).Val |= arch.MAP_FIXED
	case "provision":
		if pid, ok := c.Args[0].(*prog.ConstArg); ok && uint32(pid.Val) == ^uint32(0) {
			// PID -1 causes some debugging splat on console.
			pid.Val = 0
		}
	}
}
