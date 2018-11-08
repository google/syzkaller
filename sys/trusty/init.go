// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package trusty

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type arch struct {
}

func InitTarget(target *prog.Target) {
	arch := &arch{}
	target.MakeMmap = targets.MakeSyzMmap(target)
	target.SanitizeCall = arch.sanitizeCall
}

func (arch *arch) sanitizeCall(c *prog.Call) {
}
