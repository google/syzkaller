// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/hash"
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

func TestExecuteSeedCachedErrors(t *testing.T) {
	img := filepath.Join(t.TempDir(), "img")
	require.NoError(t, os.WriteFile(img, nil, 0600))
	imgHash, err := hash.File(img)
	require.NoError(t, err)

	prog := "getrlimit(0x0, 0x0)\n"
	state := reproduceState{
		TargetOS:   "linux",
		TargetArch: "amd64",
		Image:      img,
		VM:         json.RawMessage("{}"),
	}
	desc := fmt.Sprintf("seed-exec: kernel commit , kernel config hash %v, image hash %v,"+
		" vm , vm config hash %v, syz repro hash %v",
		hash.String(""), imgHash.String(), hash.String(state.VM), hash.String(prog))

	tests := []struct {
		name      string
		cached    map[string]any
		wantError string
	}{
		{
			name:      "execution error",
			cached:    map[string]any{"Error": "process failed"},
			wantError: "process failed",
		},
		{
			name:      "kernel crash",
			cached:    map[string]any{"BugTitle": "KASAN: use-after-free"},
			wantError: "kernel crashed: KASAN: use-after-free",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := aflow.NewTestContext(t)
			_, _, err := aflow.CacheObject(ctx, "seed-exec", desc, func() (map[string]any, error) {
				return tc.cached, nil
			})
			require.NoError(t, err)
			_, err = executeSeed(ctx, state, ExecuteSeedArgs{
				ReproSyz: prog,
			})
			require.ErrorContains(t, err, tc.wantError)
			require.IsType(t, aflow.BadCallError(""), err)
		})
	}
}

func TestGetExecutedProgram(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	syzProg := "openat$dir(0xffffffffffffff9c, &AUTO='./file0\\x00', 0x0, 0x0)\n"
	callErrors := []crash.CallError{
		{Index: 0, CallName: "openat$dir", Errno: 2, Error: "no such file or directory"},
	}
	_, cachedID, err := aflow.CacheObject(ctx, "seed-exec", "test execution", func() (map[string]any, error) {
		return map[string]any{
			"GeneratedSyz": syzProg,
			"CallErrors":   callErrors,
		}, nil
	})
	require.NoError(t, err)

	res, err := getExecutedProgram(ctx, reproduceState{}, GetExecutedProgramArgs{ExecutionCachedID: cachedID})
	require.NoError(t, err)
	require.Equal(t, GetExecutedProgramResult{
		SyzProgram: syzProg,
		CallErrors: callErrors,
	}, res)

	_, err = getExecutedProgram(ctx, reproduceState{}, GetExecutedProgramArgs{ExecutionCachedID: "seed-exec/missing"})
	require.Error(t, err)
	require.IsType(t, aflow.BadCallError(""), err)
}
