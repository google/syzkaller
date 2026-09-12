// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gvisor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func TestExtract(t *testing.T) {
	dir := t.TempDir()
	extractDir := filepath.Join(dir, "extracted")

	// Make a fake release tarball.
	release := filepath.Join(dir, "release")
	files := []string{"runsc", "other", "gvisor-bin/gvisor_sentry", "gvisor-bin/dir/nested"}
	for _, file := range files {
		path := filepath.Join(release, filepath.FromSlash(file))
		require.NoError(t, osutil.MkdirAll(filepath.Dir(path)))
		require.NoError(t, os.WriteFile(path, []byte(file), 0755))
	}
	tarball := filepath.Join(dir, "image")
	_, err := osutil.RunCmd(time.Minute, release, "tar", "-cjf", tarball, ".")
	require.NoError(t, err)

	// Extract twice to ensure that extracting over an existing dir also works.
	for range 2 {
		got, err := Extract(tarball, extractDir)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(extractDir, "runsc"), got)
		for _, file := range files {
			require.True(t, osutil.IsExist(filepath.Join(extractDir, filepath.FromSlash(file))), file)
		}
	}
}
