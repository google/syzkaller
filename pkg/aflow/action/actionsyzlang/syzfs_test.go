// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func syzkallerRepoRoot(t *testing.T) string {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root with go.mod not found")
		}
		dir = parent
	}
}

func TestPrepareSyzFS(t *testing.T) {
	res, err := prepareSyzFSFunc(nil, PrepareSyzFSArgs{
		Syzkaller: syzkallerRepoRoot(t),
		TargetOS:  targets.Linux,
	})
	require.NoError(t, err)
	require.NotNil(t, res.SyzFS)
	require.Contains(t, res.DescriptionFilesPrompt, "Available Syscall Description Files:\n")
	require.Contains(t, res.DescriptionFilesPrompt, "sys.txt\n")
	require.NotContains(t, res.DescriptionFilesPrompt, "sys.txt.const\n")
}
