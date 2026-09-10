// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import "strings"

// Capabilities represents the hardware and virtualization capabilities
// of the target environment (e.g. CPU vendor, nested virtualization support).
// Used to filter boot/image unit tests based on target capabilities.
type Capabilities struct {
	CPUVendor string `json:"vendor,omitempty"`
	Nested    *bool  `json:"nested,omitempty"`
}

// Properties converts the capabilities into a set of property strings matching
// boot test `# requires:` constraints (e.g. "vendor=intel", "nested").
func (caps *Capabilities) Properties() map[string]bool {
	if caps == nil {
		return make(map[string]bool)
	}
	props := make(map[string]bool)
	if vendor := strings.ToLower(strings.TrimSpace(caps.CPUVendor)); vendor != "" {
		props["vendor="+vendor] = true
	}
	if caps.Nested != nil && *caps.Nested {
		props["nested"] = true
	}
	return props
}

// Merge copies non-empty/non-nil fields from other into caps.
// Pointer fields such as Nested are cloned to avoid shared mutable state.
func (caps *Capabilities) Merge(other *Capabilities) {
	if caps == nil || other == nil {
		return
	}
	if other.CPUVendor != "" {
		caps.CPUVendor = other.CPUVendor
	}
	if other.Nested != nil {
		val := *other.Nested
		caps.Nested = &val
	}
}
