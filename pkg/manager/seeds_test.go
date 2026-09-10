// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequires(t *testing.T) {
	{
		requires := parseRequires([]byte("# requires: manual arch=amd64"))
		assert.True(t, checkArch(requires, "amd64"))
		assert.False(t, checkArch(requires, "riscv64"))
	}
	{
		requires := parseRequires([]byte("# requires: -arch=arm64 manual -arch=riscv64"))
		assert.True(t, checkArch(requires, "amd64"))
		assert.False(t, checkArch(requires, "riscv64"))
	}
}

func TestMatchRequirements(t *testing.T) {
	tests := []struct {
		name     string
		props    map[string]bool
		requires map[string]bool
		want     bool
	}{
		{
			name: "positive match",
			props: map[string]bool{
				"nested": true,
			},
			requires: map[string]bool{
				"nested": true,
			},
			want: true,
		},
		{
			name:  "missing positive match",
			props: map[string]bool{},
			requires: map[string]bool{
				"nested": true,
			},
			want: false,
		},
		{
			name: "negative match (absent)",
			props: map[string]bool{
				"threaded": false, // or absent
			},
			requires: map[string]bool{
				"threaded": false,
			},
			want: true,
		},
		{
			name: "negative match (present but false)",
			props: map[string]bool{
				"threaded": false,
			},
			requires: map[string]bool{
				"threaded": false,
			},
			want: true,
		},
		{
			name: "negative mismatch (present and true)",
			props: map[string]bool{
				"threaded": true,
			},
			requires: map[string]bool{
				"threaded": false,
			},
			want: false,
		},
		{
			name: "key-value match",
			props: map[string]bool{
				"vendor=intel": true,
			},
			requires: map[string]bool{
				"vendor=intel": true,
			},
			want: true,
		},
		{
			name: "key-value mismatch",
			props: map[string]bool{
				"vendor=amd": true,
			},
			requires: map[string]bool{
				"vendor=intel": true,
			},
			want: false,
		},
		{
			name: "multiple requirements (all match)",
			props: map[string]bool{
				"arch=amd64":   true,
				"vendor=intel": true,
				"nested":       true,
			},
			requires: map[string]bool{
				"arch=amd64":   true,
				"vendor=intel": true,
				"nested":       true,
			},
			want: true,
		},
		{
			name: "multiple requirements (one mismatch)",
			props: map[string]bool{
				"arch=amd64": true,
				"vendor=amd": true,
				"nested":     true,
			},
			requires: map[string]bool{
				"arch=amd64":   true,
				"vendor=intel": true,
				"nested":       true,
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchRequirements(tc.props, tc.requires)
			assert.Equal(t, tc.want, got)
		})
	}
}
