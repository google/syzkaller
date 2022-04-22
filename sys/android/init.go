// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package android

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/linux"
)

func InitTarget(target *prog.Target) {
	linux.InitTarget(target)
}
