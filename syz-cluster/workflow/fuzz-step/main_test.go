// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestShouldSkipFuzzing(t *testing.T) {
	t.Run("one empty", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(nil, map[string]string{"A": "1"}))
	})
	t.Run("equal", func(t *testing.T) {
		assert.True(t, shouldSkipFuzzing(
			map[string]string{"A": "1", "B": "2"},
			map[string]string{"A": "1", "B": "2"},
		))
	})
	t.Run("same len, different hashes", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(
			map[string]string{"A": "1", "B": "2"},
			map[string]string{"A": "1", "B": "different"},
		))
	})
	t.Run("different len, same hashes", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(
			map[string]string{"A": "1", "B": "2", "C": "3"},
			map[string]string{"A": "1", "B": "2"},
		))
	})
}
