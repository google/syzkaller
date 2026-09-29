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

func TestCapabilitiesCheck(t *testing.T) {
	tests := []struct {
		name     string
		caps     *Capabilities
		required *Capabilities
		wantErr  bool
	}{
		{
			"nil required",
			&Capabilities{CPUVendor: "intel", Nested: true},
			nil,
			false,
		},
		{
			"empty required",
			&Capabilities{CPUVendor: "intel"},
			&Capabilities{},
			false,
		},
		{
			"exact match",
			&Capabilities{CPUVendor: "intel", Nested: true},
			&Capabilities{CPUVendor: "intel", Nested: true},
			false,
		},
		{
			"subset match",
			&Capabilities{CPUVendor: "intel", Nested: true},
			&Capabilities{Nested: true},
			false,
		},
		{
			"missing nested",
			&Capabilities{CPUVendor: "intel", Nested: false},
			&Capabilities{Nested: true},
			true,
		},
		{
			"vendor mismatch",
			&Capabilities{CPUVendor: "amd", Nested: true},
			&Capabilities{CPUVendor: "intel"},
			true,
		},
		{
			"nil caps with non-empty required",
			nil,
			&Capabilities{Nested: true},
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.caps.Check(tc.required)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
