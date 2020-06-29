// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/google/syzkaller/prog"
)

func isSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	if strings.HasPrefix(c.CallName, "ioctl$VMM_") {
		return isSupportedVMM()
	}
	return true, ""
}

func isSupportedVMM() (bool, string) {
	device := "/dev/vmm"
	fd, err := syscall.Open(device, syscall.O_RDONLY, 0)
	if fd == -1 {
		return false, fmt.Sprintf("open(%v) failed: %v", device, err)
	}
	syscall.Close(fd)
	return true, ""
}

func init() {
	checkFeature[FeatureCoverage] = unconditionallyEnabled
	checkFeature[FeatureComparisons] = unconditionallyEnabled
	checkFeature[FeatureExtraCoverage] = unconditionallyEnabled
	checkFeature[FeatureNetInjection] = unconditionallyEnabled
	checkFeature[FeatureSandboxSetuid] = unconditionallyEnabled
}
