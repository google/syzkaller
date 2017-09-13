// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	"runtime"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys/linux"
)

func init() {
	if err := prog.SetDefaultTarget("linux", runtime.GOARCH); err != nil {
		panic(err)
	}
}
