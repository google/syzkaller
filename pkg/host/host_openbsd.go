// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"github.com/google/syzkaller/prog"
)

func isSupported(c *prog.Syscall, sandbox string) (bool, string) {
	return true, ""
}

func init() {
	checkFeature[FeatureCoverage] = unconditionallyEnabled
}
