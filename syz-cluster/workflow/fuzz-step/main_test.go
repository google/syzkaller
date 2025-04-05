// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"io/fs"
	"path/filepath"
	"testing"
)

func TestConfigLoad(t *testing.T) {
	root := filepath.Join("..", "configs")
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || path == root {
			return nil
		}
		t.Logf("checking %v", path)
		_, _, err = loadConfigs(root, d.Name(), false)
		if err != nil {
			t.Fatalf("error proessing %q: %v", path, err)
		}
		return nil
	})
}
