// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestResolveSyzlangDependencies(t *testing.T) {
	resetSyzFS()

	ctx := aflow.NewTestContext(t)
	ctx.StateMap()["TargetOS"] = targets.Linux
	ctx.StateMap()["Syzkaller"] = "../../../.."

	// Test program referencing syz_mount_image$ext4.
	program := `
r0 = syz_mount_image$ext4(&(0x7f0000000000)='ext4\x00', &(0x7f0000000100)='./file0\x00', 0x0, 0x0, 0x0, 0x0)
`
	res, err := ResolveSyzlangDependencies(ctx, struct{}{}, CodeFixerArgs{
		SyzProgram: program,
	})
	require.NoError(t, err)

	defs, ok := res["StaticDefinitions"].(string)
	require.True(t, ok)
	require.NotEmpty(t, defs)

	// Verify that the output contains the syscall definition of syz_mount_image.
	require.Contains(t, defs, "syz_mount_image$ext4")

	// Verify that the output also contains referenced type/struct/resource definitions
	// (e.g. filename, flags, or other dependencies referenced in the filesystem descriptions).
	require.Contains(t, defs, "filename")
}
