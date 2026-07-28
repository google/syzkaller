// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	aflow_syzlang "github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/prog"
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

func TestFormatCallErrors(t *testing.T) {
	calls := []*prog.Call{
		{Meta: &prog.Syscall{Name: "syz_usb_connect"}},
		{Meta: &prog.Syscall{Name: "openat"}},
		{Meta: &prog.Syscall{Name: "read"}},
	}

	execFinished := flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished
	execStarted := flatrpc.CallFlagExecuted
	unexec := flatrpc.CallFlag(0)

	tests := []struct {
		name       string
		callErrors []crash.CallError
		want       []CallError
	}{
		{
			name: "normal errno formatting",
			callErrors: []crash.CallError{
				{Flags: execFinished, Errno: 0},
				{Flags: execFinished, Errno: 22},
				{Flags: execFinished, Errno: 0},
			},
			want: []CallError{
				{Index: 1, CallName: "openat", Errno: 22, Error: "invalid argument"},
			},
		},
		{
			name: "unexecuted and timed out calls",
			callErrors: []crash.CallError{
				{Flags: execStarted, Errno: 998},
				{Flags: unexec, Errno: 998},
			},
			want: []CallError{
				{Index: 0, CallName: "syz_usb_connect", Errno: 998, Error: "call execution timed out or hung"},
				{Index: 1, CallName: "openat", Errno: 998, Error: "call unexecuted (executor halted on an earlier call)"},
			},
		},
		{
			name: "mix of finished errno, timed out, and unexecuted",
			callErrors: []crash.CallError{
				{Flags: execFinished, Errno: 22},
				{Flags: execStarted, Errno: 998},
				{Flags: unexec, Errno: 998},
			},
			want: []CallError{
				{Index: 0, CallName: "syz_usb_connect", Errno: 22, Error: "invalid argument"},
				{Index: 1, CallName: "openat", Errno: 998, Error: "call execution timed out or hung"},
				{Index: 2, CallName: "read", Errno: 998, Error: "call unexecuted (executor halted on an earlier call)"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatCallErrors(tt.callErrors, 0, calls)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
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
