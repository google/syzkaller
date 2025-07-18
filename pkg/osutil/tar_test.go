// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTarDirectory(t *testing.T) {
	dir := t.TempDir()
	items := map[string]string{
		"file1.txt":     "first file content",
		"dir/file2.txt": "second file content",
		"empty.txt":     "",
	}
	require.NoError(t, FillDirectory(dir, items))

	var buf bytes.Buffer
	err := tarDirectory(dir, &buf)
	assert.NoError(t, err)

	tr := tar.NewReader(&buf)
	found := make(map[string]string)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			contentBytes, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			found[hdr.Name] = string(contentBytes)
		}
	}

	assert.Equal(t, items, found)
}
