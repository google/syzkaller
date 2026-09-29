// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"fmt"
	"strings"
)

// Capabilities represents the hardware and virtualization capabilities
// of the target environment (e.g. CPU vendor, nested virtualization support).
// Used to filter boot/image unit tests based on target capabilities.
type Capabilities struct {
	CPUVendor string `json:"vendor,omitempty"`
	Nested    bool   `json:"nested,omitempty"`
}

// Properties converts the capabilities into a set of property strings matching
// boot test `# requires:` constraints (e.g. "vendor=intel", "nested").
func (caps *Capabilities) Properties() map[string]bool {
	props := make(map[string]bool)
	if caps == nil {
		return props
	}
	if vendor := strings.ToLower(strings.TrimSpace(caps.CPUVendor)); vendor != "" {
		props["vendor="+vendor] = true
	}
	if caps.Nested {
		props["nested"] = true
	}
	return props
}

// Check verifies that all capabilities specified in required are present in caps.
func (caps *Capabilities) Check(required *Capabilities) error {
	have := caps.Properties()
	for prop := range required.Properties() {
		if !have[prop] {
			return fmt.Errorf("required capability %q is not supported by the target machine", prop)
		}
	}
	return nil
}
