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
		{"positive match", map[string]bool{"nested": true}, map[string]bool{"nested": true}, true},
		{"missing positive match", map[string]bool{}, map[string]bool{"nested": true}, false},
		{"negative match (absent)", map[string]bool{}, map[string]bool{"threaded": false}, true},
		{
			"negative match (false)",
			map[string]bool{"threaded": false},
			map[string]bool{"threaded": false},
			true,
		},
		{"negative mismatch", map[string]bool{"threaded": true}, map[string]bool{"threaded": false}, false},
		{
			"key-value match",
			map[string]bool{"vendor=intel": true},
			map[string]bool{"vendor=intel": true},
			true,
		},
		{
			"key-value mismatch",
			map[string]bool{"vendor=amd": true},
			map[string]bool{"vendor=intel": true},
			false,
		},
		{
			"multiple requirements (all match)",
			map[string]bool{"arch=amd64": true, "vendor=intel": true, "nested": true},
			map[string]bool{"arch=amd64": true, "vendor=intel": true, "nested": true},
			true,
		},
		{
			"multiple requirements (one mismatch)",
			map[string]bool{"arch=amd64": true, "vendor=amd": true, "nested": true},
			map[string]bool{"arch=amd64": true, "vendor=intel": true, "nested": true},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MatchRequirements(tc.props, tc.requires))
		})
	}
}
