// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSandboxRootFIFO(t *testing.T) {
	root, rootDir, _ := makeSandboxRoot(t)
	const fifo = "fifo"
	require.NoError(t, syscall.Mkfifo(filepath.Join(rootDir, fifo), 0600))

	// Reading must fail rather than block until there is a writer.
	_, err := root.ReadFile(fifo)
	require.Error(t, err)
	dst := filepath.Join(t.TempDir(), "dst")
	require.Error(t, root.CopyFileTo(fifo, dst))
	require.Error(t, CopyFile(filepath.Join(rootDir, fifo), dst))
	assert.NoFileExists(t, dst)

	// Writing must replace the FIFO rather than block until there is a reader.
	require.NoError(t, root.WriteFile(fifo, []byte("data")))
	data, err := os.ReadFile(filepath.Join(rootDir, fifo))
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), data)
}

func TestSandboxRootWriteFileOwner(t *testing.T) {
	RequireSandbox(t)
	root, rootDir, _ := makeSandboxRoot(t)
	require.NoError(t, root.WriteFile("file", []byte("data")))
	assert.True(t, IsSandboxOwned(t, filepath.Join(rootDir, "file")))
}
