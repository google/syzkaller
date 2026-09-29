// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCapabilitiesProperties(t *testing.T) {
	tests := []struct {
		name string
		caps *Capabilities
		want map[string]bool
	}{
		{"nil", nil, map[string]bool{}},
		{"empty", &Capabilities{}, map[string]bool{}},
		{"vendor only", &Capabilities{CPUVendor: "intel"}, map[string]bool{"vendor=intel": true}},
		{"vendor case normalization", &Capabilities{CPUVendor: "Intel"}, map[string]bool{"vendor=intel": true}},
		{"nested true only", &Capabilities{Nested: true}, map[string]bool{"nested": true}},
		{"nested false only", &Capabilities{Nested: false}, map[string]bool{}},
		{
			"both",
			&Capabilities{CPUVendor: "amd", Nested: true},
			map[string]bool{"vendor=amd": true, "nested": true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.caps.Properties())
		})
	}
}
