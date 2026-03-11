// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormat(t *testing.T) {
	// Test valid program.
	validProg := `r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
write(r0, &AUTO="01010101", 0x4)
`
	res, err := formatActionFunc(nil, FormatArgs{CandidateReproSyz: validProg})
	require.NoError(t, err)
	require.NotEmpty(t, res.ReproSyz)

	// Test invalid program.
	invalidProg := `r0 = unknown_syscall_name(0x123)`
	_, err2 := formatActionFunc(nil, FormatArgs{CandidateReproSyz: invalidProg})
	require.Error(t, err2)
	require.Contains(t, err2.Error(), "unknown syscall")
}
