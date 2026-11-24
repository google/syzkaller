// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ai

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidKernelFuncName(t *testing.T) {
	valid := []string{
		"foo",
		"_bar_123",
		"__x64_sys_ioctl",
		"netlink_sendmsg.constprop.0",
		"do_something.isra.0",
		strings.Repeat("a", maxKernelFuncNameLen),
	}
	for _, name := range valid {
		assert.True(t, ValidKernelFuncName(name), "expected valid: %q", name)
	}

	invalid := []string{
		"",
		"123foo",
		".foo",
		"foo.",
		"foo..bar",
		"foo bar",
		"foo\nbar",
		"foo;bar",
		"foo()",
		"foo/bar",
		strings.Repeat("a", maxKernelFuncNameLen+1),
	}
	for _, name := range invalid {
		assert.False(t, ValidKernelFuncName(name), "expected invalid: %q", name)
	}
}
