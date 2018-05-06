// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package test

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/sys/test/gen"
)

func init() {
	prog.RegisterTarget(gen.Target_32, initTarget)
	prog.RegisterTarget(gen.Target_64, initTarget)
}

func initTarget(target *prog.Target) {
	target.MakeMmap = targets.MakeSyzMmap(target)
}
