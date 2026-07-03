// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package freebsd contains target initialization and syscall neutralization logic.
package freebsd

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
	arch := &arch{
		unix: targets.MakeUnixNeutralizer(target),
	}

	target.MakeDataMmap = targets.MakePosixMmap(target, true, false)
	target.Neutralize = arch.unix.Neutralize
}

type arch struct {
	unix *targets.UnixNeutralizer
}
