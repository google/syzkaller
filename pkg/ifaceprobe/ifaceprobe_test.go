// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifaceprobe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractFileFilter(t *testing.T) {
	allow := func(file string) bool {
		return file != "/sys/forbidden"
	}
	for _, p := range []string{
		"/dev/null",
		"/sys/allowed",
	} {
		assert.True(t, extractFileFilter(p, allow), "path: %q", p)
	}
	for _, p := range []string{
		"/sys/forbidden",
		"/proc/123/maps",
	} {
		assert.False(t, extractFileFilter(p, allow), "path: %q", p)
	}
}

func TestInfoFilterFiles(t *testing.T) {
	info := &Info{
		Files: []FileInfo{
			{Name: "/dev/null", Cover: []int{0}},
			{Name: "/sys/forbidden", Cover: []int{1}},
			{Name: "/sys/allowed", Cover: []int{2}},
		},
	}
	info.FilterFiles(func(file string) bool {
		return file != "/sys/forbidden"
	})
	assert.Equal(t, []FileInfo{
		{Name: "/dev/null", Cover: []int{0}},
		{Name: "/sys/allowed", Cover: []int{2}},
	}, info.Files)
}
