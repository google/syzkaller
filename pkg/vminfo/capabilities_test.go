// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCapabilitiesProperties(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name string
		caps *Capabilities
		want map[string]bool
	}{
		{
			name: "nil",
			caps: nil,
			want: map[string]bool{},
		},
		{
			name: "empty",
			caps: &Capabilities{},
			want: map[string]bool{},
		},
		{
			name: "vendor only",
			caps: &Capabilities{
				CPUVendor: "intel",
			},
			want: map[string]bool{
				"vendor=intel": true,
			},
		},
		{
			name: "vendor case normalization",
			caps: &Capabilities{
				CPUVendor: "Intel",
			},
			want: map[string]bool{
				"vendor=intel": true,
			},
		},
		{
			name: "nested true only",
			caps: &Capabilities{
				Nested: &trueVal,
			},
			want: map[string]bool{
				"nested": true,
			},
		},
		{
			name: "nested false only",
			caps: &Capabilities{
				Nested: &falseVal,
			},
			want: map[string]bool{},
		},
		{
			name: "both",
			caps: &Capabilities{
				CPUVendor: "amd",
				Nested:    &trueVal,
			},
			want: map[string]bool{
				"vendor=amd": true,
				"nested":     true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.caps.Properties()
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCapabilitiesMerge(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name  string
		base  *Capabilities
		other *Capabilities
		want  *Capabilities
	}{
		{
			name:  "merge nil other",
			base:  &Capabilities{CPUVendor: "intel", Nested: &trueVal},
			other: nil,
			want:  &Capabilities{CPUVendor: "intel", Nested: &trueVal},
		},
		{
			name:  "merge into empty",
			base:  &Capabilities{},
			other: &Capabilities{CPUVendor: "amd", Nested: &falseVal},
			want:  &Capabilities{CPUVendor: "amd", Nested: &falseVal},
		},
		{
			name:  "override vendor keep nested",
			base:  &Capabilities{CPUVendor: "intel", Nested: &trueVal},
			other: &Capabilities{CPUVendor: "amd"},
			want:  &Capabilities{CPUVendor: "amd", Nested: &trueVal},
		},
		{
			name:  "override nested keep vendor",
			base:  &Capabilities{CPUVendor: "intel", Nested: &trueVal},
			other: &Capabilities{Nested: &falseVal},
			want:  &Capabilities{CPUVendor: "intel", Nested: &falseVal},
		},
		{
			name:  "empty other leaves base unchanged",
			base:  &Capabilities{CPUVendor: "intel", Nested: &trueVal},
			other: &Capabilities{},
			want:  &Capabilities{CPUVendor: "intel", Nested: &trueVal},
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

		// Mutating other's underlying boolean should not mutate base.
		*other.Nested = false
		assert.True(t, *base.Nested)
	})
}
