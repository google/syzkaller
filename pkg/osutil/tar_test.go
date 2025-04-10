// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"archive/tar"
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTarDirectory(t *testing.T) {
	dir := t.TempDir()

	items := map[string]string{
		"file1.txt":     "first file content",
		"dir/file2.txt": "second file content",
		"empty.txt":     "",
	}

	for path, content := range items {
		fullPath := filepath.Join(dir, path)
		dirPath := filepath.Dir(fullPath)
		if err := MkdirAll(dirPath); err != nil {
			t.Fatalf("mkdir %q failed: %v", dirPath, err)
		}
		if err := WriteFile(fullPath, []byte(content)); err != nil {
			t.Fatalf("write file failed: %v", err)
		}
	}

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
