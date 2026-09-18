// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveFileMode(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.json")
	err := os.WriteFile(file, []byte("{}"), 0644)
	require.NoError(t, err)

	err = SaveFileMode(file, map[string]string{"key": "value"}, 0600)
	require.NoError(t, err)

	info, err := os.Stat(file)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	var cfg map[string]string
	err = LoadFile(file, &cfg)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"key": "value"}, cfg)
}
