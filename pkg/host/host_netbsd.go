// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

func isSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	switch c.CallName {
	case "syz_usb_connect", "syz_usb_disconnect":
		reason := checkUSBEmulation()
		return reason == "", reason
	default:
		return true, ""
	}
}

func init() {
	checkFeature[FeatureCoverage] = unconditionallyEnabled
	checkFeature[FeatureComparisons] = unconditionallyEnabled
	checkFeature[FeatureUSBEmulation] = checkUSBEmulation
	checkFeature[FeatureExtraCoverage] = checkUSBEmulation
	checkFeature[FeatureFault] = checkFault
}

func checkUSBEmulation() string {
	if err := osutil.IsAccessible("/dev/vhci0"); err != nil {
		return err.Error()
	}
	return ""
}

func checkFault() string {
	if err := osutil.IsAccessible("/dev/fault"); err != nil {
		return err.Error()
	}
	return ""
}
