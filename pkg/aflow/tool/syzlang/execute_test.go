// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	aflow_syzlang "github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/image"
	"github.com/stretchr/testify/require"
)

func TestExecuteSeed_DeserializeErrors(t *testing.T) {
	tests := []struct {
		name    string
		program string
	}{
		{
			name:    "double quotes",
			program: `openat(0xffffffffffffff9c, "hello", 0x0, 0x0)`,
		},
		{
			name: "multi-line statement",
			program: `openat(0xffffffffffffff9c,
0x0, 0x0)`,
		},
		{
			name:    "inline comment",
			program: `openat(0xffffffffffffff9c, # inline comment`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &aflow.Context{}
			state := reproduceState{
				TargetOS:   "linux",
				TargetArch: "amd64",
			}
			args := ExecuteSeedArgs{
				ReproSyz: tc.program,
			}
			_, err := executeSeed(ctx, state, args)
			require.Error(t, err)
			require.Contains(t, err.Error(), deserializationErrorHelp)
		})
	}
}

func TestExecuteSeed_BlobPlaceholder(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	compressed := image.Compress(data)
	b64 := image.EncodeB64(compressed)
	input := fmt.Sprintf(
		`syz_mount_image$btrfs(&AUTO='btrfs\x00', &AUTO='./file0\x00', 0x0, &AUTO, 0x1, AUTO, &AUTO="$%s")`,
		b64,
	)

	programWithPlaceholder := aflow_syzlang.ReplaceBlobs(input)
	require.Contains(t, programWithPlaceholder, "$BLOB_")

	ctx := &aflow.Context{}
	state := reproduceState{
		TargetOS:   "linux",
		TargetArch: "amd64",
	}
	args := ExecuteSeedArgs{
		ReproSyz: programWithPlaceholder,
	}

	// Since state.Image is empty, executeSeed only compiles/deserializes the program.
	res, err := executeSeed(ctx, state, args)
	require.NoError(t, err)
	require.Empty(t, res.ExecutionCachedID)
}

func TestFormatDeserializeError_BlobPlaceholder(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	compressed := image.Compress(data)
	b64 := image.EncodeB64(compressed)

	rawErr := fmt.Errorf("invalid compressed data: could not read data with zlib: unexpected EOF\n"+
		"line #1: syz_mount_image$btrfs(..., &AUTO=\"$%s\")", b64)

	input := fmt.Sprintf(`syz_mount_image$btrfs(..., &AUTO="$%s")`, b64)
	placeholder := aflow_syzlang.ReplaceBlobs(input)
	require.Contains(t, placeholder, "$BLOB_")

	err := formatDeserializeError(rawErr, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "$BLOB_")
	require.NotContains(t, err.Error(), fmt.Sprintf("$%s", b64))
}
