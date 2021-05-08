// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package darwin

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
	arch := &arch{
		unix: targets.MakeUnixNeutralizer(target),
	}

	target.MakeDataMmap = targets.MakePosixMmap(target, false, false)
	target.Neutralize = arch.unix.Neutralize
}

type arch struct {
	unix *targets.UnixNeutralizer
}
