// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
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
			require.Contains(t, err.Error(), "Syzlang Syntax Reminders:")
		})
	}
}

func TestTruncateConsoleOutput(t *testing.T) {
	shortLog := "line1\nline2\nline3"
	gotShort := truncateConsoleOutput(shortLog, 5)
	require.Equal(t, shortLog, gotShort)

	lines := make([]string, 300)
	for i := range 300 {
		lines[i] = fmt.Sprintf("line %d", i+1)
	}
	longLog := strings.Join(lines, "\n")

	gotTruncated := truncateConsoleOutput(longLog, 200)
	require.Contains(t, gotTruncated, "... [VM console output truncated, showing last 200 of 300 lines] ...")
	require.NotContains(t, gotTruncated, "line 1\n")
	require.NotContains(t, gotTruncated, "line 100\n")
	require.Contains(t, gotTruncated, "line 101")
	require.Contains(t, gotTruncated, "line 300")
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

	ctx := &aflow.Context{}
	programWithPlaceholder := ctx.ReplaceBlobs(input)
	require.Contains(t, programWithPlaceholder, "$BLOB_")

	state := reproduceState{
		TargetOS:   "linux",
		TargetArch: "amd64",
	}
	args := ExecuteSeedArgs{
		ReproSyz: programWithPlaceholder,
	}

	_, err := executeSeed(ctx, state, args)
	require.ErrorContains(t, err, "VM configuration is missing")
}

func TestExecuteSeed_BlobPlaceholderError(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	compressed := image.Compress(data)
	b64 := image.EncodeB64(compressed)

	input := fmt.Sprintf(`syz_mount_image$btrfs(invalid_arg, &AUTO="$%s")`, b64)
	ctx := &aflow.Context{}
	programWithPlaceholder := ctx.ReplaceBlobs(input)
	require.Contains(t, programWithPlaceholder, "$BLOB_")

	state := reproduceState{
		TargetOS:   "linux",
		TargetArch: "amd64",
	}
	args := ExecuteSeedArgs{
		ReproSyz: programWithPlaceholder,
	}

	_, err := executeSeed(ctx, state, args)
	require.Error(t, err)
	require.Contains(t, err.Error(), "$BLOB_")
	require.NotContains(t, err.Error(), fmt.Sprintf("$%s", b64))
}

func TestExecuteSeed(t *testing.T) {
	state := reproduceState{
		TargetOS:   "linux",
		TargetArch: "amd64",
		Syzkaller:  "../../../..",
	}

	tests := []struct {
		name      string
		program   string
		wantError string
	}{
		{
			name:      "valid program",
			program:   "getrlimit(0x0, 0x0)",
			wantError: "VM configuration is missing",
		},
		{
			name:      "empty program",
			program:   "",
			wantError: "syz program cannot be empty",
		},
		{
			name:      "invalid program syntax",
			program:   "invalid_call()",
			wantError: "unknown syscall",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := executeSeed(&aflow.Context{}, state, ExecuteSeedArgs{
				ReproSyz: tc.program,
			})
			if tc.wantError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
