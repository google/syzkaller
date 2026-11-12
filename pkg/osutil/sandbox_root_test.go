// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeSandboxRoot creates a test dir with a secret file, and a SandboxRoot dir inside of it
// with symlinks escaping to the secret file and the outer dir.
func makeSandboxRoot(t *testing.T) (root *SandboxRoot, rootDir, secretFile string) {
	outerDir := t.TempDir()
	secretFile = filepath.Join(outerDir, "secret.txt")
	require.NoError(t, WriteFile(secretFile, []byte("secret")))
	rootDir = filepath.Join(outerDir, "root")
	require.NoError(t, MkdirAll(rootDir))
	require.NoError(t, os.Symlink(secretFile, filepath.Join(rootDir, "escape.txt")))
	require.NoError(t, os.Symlink(outerDir, filepath.Join(rootDir, "escapedir")))
	root, err := OpenSandboxRoot(rootDir)
	require.NoError(t, err)
	t.Cleanup(func() { root.Close() })
	return root, rootDir, secretFile
}

func TestSandboxRootCopyFileTo(t *testing.T) {
	root, rootDir, _ := makeSandboxRoot(t)
	okFile := filepath.Join(rootDir, "ok.txt")
	require.NoError(t, WriteFile(okFile, []byte("ok")))
	require.NoError(t, os.Chmod(okFile, 0755))
	require.NoError(t, os.Symlink("ok.txt", filepath.Join(rootDir, "link.txt")))

	dst := filepath.Join(t.TempDir(), "dst")
	for _, p := range []string{"ok.txt", "link.txt"} {
		require.NoError(t, os.RemoveAll(dst))
		require.NoError(t, root.CopyFileTo(p, dst), p)
		data, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.Equal(t, []byte("ok"), data, p)
		stat, err := os.Lstat(dst)
		require.NoError(t, err)
		assert.Zero(t, stat.Mode()&0111, p)
	}

	require.NoError(t, os.RemoveAll(dst))
	for _, p := range []string{"../secret.txt", "escape.txt", "escapedir/secret.txt", "."} {
		require.Error(t, root.CopyFileTo(p, dst), p)
		assert.NoFileExists(t, dst, p)
	}
}

func TestSandboxRootWriteFile(t *testing.T) {
	root, rootDir, secretFile := makeSandboxRoot(t)
	require.NoError(t, WriteFile(filepath.Join(rootDir, "existing.txt"), []byte("old")))
	require.NoError(t, os.Symlink(secretFile, filepath.Join(rootDir, "symlink.txt")))
	require.NoError(t, os.Link(secretFile, filepath.Join(rootDir, "hardlink.txt")))

	// Links must be replaced with regular files rather than written through.
	files := []string{"new.txt", "existing.txt", "symlink.txt", "hardlink.txt", "escape.txt"}
	for _, p := range files {
		require.NoError(t, root.WriteFile(p, []byte("new")), p)
		stat, err := os.Lstat(filepath.Join(rootDir, p))
		require.NoError(t, err)
		assert.True(t, stat.Mode().IsRegular(), p)
		data, err := os.ReadFile(filepath.Join(rootDir, p))
		require.NoError(t, err)
		assert.Equal(t, []byte("new"), data, p)
	}

	for _, p := range []string{"../escape.txt", "escapedir/escape.txt"} {
		require.Error(t, root.WriteFile(p, []byte("new")), p)
	}
	assert.NoFileExists(t, filepath.Join(filepath.Dir(rootDir), "escape.txt"))

	data, err := os.ReadFile(secretFile)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), data)

	// No temporary files must be left behind.
	entries, err := os.ReadDir(rootDir)
	require.NoError(t, err)
	assert.Len(t, entries, len(files)+1)
}
