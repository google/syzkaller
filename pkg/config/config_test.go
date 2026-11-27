// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/syzkaller/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveFilePerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions are not supported on windows")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "manager.cfg")
	require.NoError(t, config.SaveFile(file, map[string]string{"dashboard_key": "secret"}))
	info, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	var cfg map[string]string
	require.NoError(t, config.LoadFile(file, &cfg))
	assert.Equal(t, "secret", cfg["dashboard_key"])
	_, err = os.Stat(file + ".tmp")
	assert.True(t, os.IsNotExist(err), "temp file is left behind: %v", err)

	// Overwriting an existing world-readable config must drop the extra permissions.
	require.NoError(t, os.Chmod(file, 0644))
	require.NoError(t, config.SaveFile(file, map[string]string{"dashboard_key": "secret2"}))
	info, err = os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
