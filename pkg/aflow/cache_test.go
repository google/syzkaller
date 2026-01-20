// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	var mockedTime time.Time
	timeNow := func() time.Time {
		return mockedTime
	}
	tempDir := t.TempDir()
	c, err := newTestCache(t, tempDir, 1<<40, timeNow)
	require.NoError(t, err)
	dir1, err := c.Create("foo", "1", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "bar"), []byte("abc"))
	})
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(dir1, "bar"))
	require.NoError(t, err)
	require.Equal(t, data, []byte("abc"))
	c.Release(dir1)

	dir2, err := c.Create("foo", "1", func(dir string) error {
		t.Fatal("must not be called")
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, dir2, dir1)
	data, err = os.ReadFile(filepath.Join(dir2, "bar"))
	require.NoError(t, err)
	require.Equal(t, data, []byte("abc"))
	c.Release(dir2)

	dir3, err := c.Create("foo", "2", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "baz"), []byte("def"))
	})
	require.NoError(t, err)
	require.NotEqual(t, dir3, dir1)
	data, err = os.ReadFile(filepath.Join(dir3, "baz"))
	require.NoError(t, err)
	require.Equal(t, data, []byte("def"))
	c.Release(dir3)

	failedDir := ""
	dir4, err := c.Create("foo", "3", func(dir string) error {
		failedDir = dir
		return fmt.Errorf("failed")
	})
	require.Error(t, err)
	require.Empty(t, dir4)
	require.False(t, osutil.IsExist(failedDir))

	// Create a new cache, it should pick up the state from disk.
	c, err = newTestCache(t, tempDir, 1<<40, timeNow)
	require.NoError(t, err)

	dir5, err := c.Create("foo", "1", func(dir string) error {
		t.Fatal("must not be called")
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, dir5, dir1)
	data, err = os.ReadFile(filepath.Join(dir5, "bar"))
	require.NoError(t, err)
	require.Equal(t, data, []byte("abc"))
	c.Release(dir5)

	// Model an incomplete dir without metadata, it should be removed.
	strayDir := filepath.Join(tempDir, "a", "b")
	require.NoError(t, osutil.MkdirAll(strayDir))
	require.NoError(t, osutil.WriteFile(filepath.Join(strayDir, "foo"), []byte("foo")))

	// With 0 max size everything unused should be purged.
	_, err = newTestCache(t, tempDir, 0, timeNow)
	require.NoError(t, err)
	require.False(t, osutil.IsExist(dir1))
	require.False(t, osutil.IsExist(dir3))
	require.False(t, osutil.IsExist(strayDir))

	// Test incremental purging of files.
	c, err = newTestCache(t, tempDir, 100<<10, timeNow)
	require.NoError(t, err)

	mockedTime = mockedTime.Add(time.Minute)
	dir6, err := c.Create("foo", "1", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "bar"), bytes.Repeat([]byte{'a'}, 5<<10))
	})
	require.NoError(t, err)
	c.Release(dir6)

	mockedTime = mockedTime.Add(time.Minute)
	dir7, err := c.Create("foo", "2", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "bar"), bytes.Repeat([]byte{'a'}, 5<<10))
	})
	require.NoError(t, err)
	c.Release(dir7)

	mockedTime = mockedTime.Add(time.Minute)
	dir8, err := c.Create("foo", "3", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "bar"), bytes.Repeat([]byte{'a'}, 60<<10))
	})
	require.NoError(t, err)
	c.Release(dir8)

	// Force update of the last access time for the first dir.
	mockedTime = mockedTime.Add(time.Minute)
	dir9, err := c.Create("foo", "1", func(dir string) error {
		t.Fatal("must not be called")
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, dir6, dir9)
	c.Release(dir9)

	// Both dirs should exist since they should fit into cache size.
	require.True(t, osutil.IsExist(dir6))
	require.True(t, osutil.IsExist(dir7))
	require.True(t, osutil.IsExist(dir8))

	mockedTime = mockedTime.Add(time.Minute)
	dir10, err := c.Create("foo", "4", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "bar"), bytes.Repeat([]byte{'a'}, 60<<10))
	})
	require.NoError(t, err)
	c.Release(dir10)

	// Two oldest dirs should be purged.
	require.True(t, osutil.IsExist(dir6))
	require.False(t, osutil.IsExist(dir7))
	require.False(t, osutil.IsExist(dir8))
	require.True(t, osutil.IsExist(dir10))
}

func TestCacheObject(t *testing.T) {
	tempDir := t.TempDir()
	c, err := newTestCache(t, tempDir, 1<<40, time.Now)
	require.NoError(t, err)
	type X struct {
		I int
		S string
	}
	dir, x, err := cacheCreateObject(c, "foo", "1", func() (X, error) {
		return X{42, "foo"}, nil
	})
	require.NoError(t, err)
	require.Equal(t, x, X{42, "foo"})
	c.Release(dir)
}
