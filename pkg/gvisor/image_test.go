// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gvisor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func TestExtract(t *testing.T) {
	dir := t.TempDir()
	extractDir := filepath.Join(dir, "extracted")

	// Make a fake release tarball.
	release := filepath.Join(dir, "release")
	files := map[string]string{
		"runsc":                    "runsc",
		"other":                    "other",
		"gvisor-bin/gvisor_sentry": "gvisor_sentry",
		"gvisor-bin/dir/nested":    "nested",
	}
	require.NoError(t, osutil.FillDirectory(release, files))
	tarball := filepath.Join(dir, "image")
	f, err := os.Create(tarball)
	require.NoError(t, err)
	require.NoError(t, osutil.TarGzDirectory(release, f))
	require.NoError(t, f.Close())

	// Extract twice to ensure that extracting over an existing dir works.
	for range 2 {
		got, err := Extract(tarball, extractDir)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(extractDir, "runsc"), got)
		for file, content := range files {
			data, err := os.ReadFile(filepath.Join(extractDir, filepath.FromSlash(file)))
			require.NoError(t, err, file)
			require.Equal(t, content, string(data), file)
		}
	}
}
