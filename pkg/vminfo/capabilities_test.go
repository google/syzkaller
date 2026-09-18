// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCapabilitiesProperties(t *testing.T) {
	trueVal, falseVal := true, false
	tests := []struct {
		name string
		caps *Capabilities
		want map[string]bool
	}{
		{"nil", nil, map[string]bool{}},
		{"empty", &Capabilities{}, map[string]bool{}},
		{"vendor only", &Capabilities{CPUVendor: "intel"}, map[string]bool{"vendor=intel": true}},
		{"vendor case normalization", &Capabilities{CPUVendor: "Intel"}, map[string]bool{"vendor=intel": true}},
		{"nested true only", &Capabilities{Nested: &trueVal}, map[string]bool{"nested": true}},
		{"nested false only", &Capabilities{Nested: &falseVal}, map[string]bool{}},
		{
			"both",
			&Capabilities{CPUVendor: "amd", Nested: &trueVal},
			map[string]bool{"vendor=amd": true, "nested": true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.caps.Properties())
		})
	}
}

func TestCapabilitiesMerge(t *testing.T) {
	trueVal, falseVal := true, false
	tests := []struct {
		name  string
		base  *Capabilities
		other *Capabilities
		want  *Capabilities
	}{
		{
			"merge nil other",
			&Capabilities{CPUVendor: "intel", Nested: &trueVal},
			nil,
			&Capabilities{CPUVendor: "intel", Nested: &trueVal},
		},
		{
			"merge into empty",
			&Capabilities{},
			&Capabilities{CPUVendor: "amd", Nested: &falseVal},
			&Capabilities{CPUVendor: "amd", Nested: &falseVal},
		},
		{
			"override vendor keep nested",
			&Capabilities{CPUVendor: "intel", Nested: &trueVal},
			&Capabilities{CPUVendor: "amd"},
			&Capabilities{CPUVendor: "amd", Nested: &trueVal},
		},
		{
			"override nested keep vendor",
			&Capabilities{CPUVendor: "intel", Nested: &trueVal},
			&Capabilities{Nested: &falseVal},
			&Capabilities{CPUVendor: "intel", Nested: &falseVal},
		},
		{
			"empty other leaves base unchanged",
			&Capabilities{CPUVendor: "intel", Nested: &trueVal},
			&Capabilities{},
			&Capabilities{CPUVendor: "intel", Nested: &trueVal},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.base.Merge(tc.other)
			assert.Equal(t, tc.want, tc.base)
		})
	}

	t.Run("nil receiver does not panic", func(t *testing.T) {
		var nilCaps *Capabilities
		require.NotPanics(t, func() {
			nilCaps.Merge(&Capabilities{CPUVendor: "intel"})
		})
	})

	t.Run("nested pointer is cloned to prevent aliasing", func(t *testing.T) {
		nested := true
		other := &Capabilities{Nested: &nested}
		base := &Capabilities{}
		base.Merge(other)
		require.NotNil(t, base.Nested)
		assert.True(t, *base.Nested)
		*other.Nested = false
		assert.True(t, *base.Nested)
	})
}
