// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuchsia

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/fuchsia/gen"
	"github.com/google/syzkaller/sys/targets"
)

func init() {
	prog.RegisterTarget(gen.Target_amd64, initTarget)
	prog.RegisterTarget(gen.Target_arm64, initTarget)
}

func initTarget(target *prog.Target) {
	target.MakeMmap = targets.MakeSyzMmap(target)
}
