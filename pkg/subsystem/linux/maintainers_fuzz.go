// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"bytes"
	"runtime"
)

func Fuzz(data []byte) int {
	parseLinuxMaintainers(bytes.NewReader(data))
	return 0
}

func init() {
	// Mark as used for deadcode checker.
	runtime.KeepAlive(Fuzz)
}
