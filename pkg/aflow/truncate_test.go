// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTruncateText(t *testing.T) {
	// Case 1: Within limit (not truncated).
	short := "line 1\nline 2\nline 3\n"
	require.Equal(t, short, TruncateText(short, 5))

	// Case 2: Exceeding limit (truncated).
	long := "line 1\nline 2\nline 3\nline 4\nline 5\n"
	want := "line 1\nline 2\n[Output truncated: showing 2 of 5 lines]"
	require.Equal(t, want, TruncateText(long, 2))
}
