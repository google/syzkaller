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

func TestCacheReadObject(t *testing.T) {
	var mockedTime time.Time
	timeNow := func() time.Time {
		return mockedTime
	}
	tempDir := t.TempDir()
	c, err := newTestCache(t, tempDir, 1<<40, timeNow)
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

	id := filepath.Base(dir)

	mockedTime = mockedTime.Add(time.Minute)
	x2, err := cacheReadObject[X](c, "foo", id, "object")
	require.NoError(t, err)
	require.Equal(t, x2, X{42, "foo"})

	entry := c.entries[dir]
	require.NotNil(t, entry)
	require.Equal(t, entry.lastUsed, mockedTime)
}

func TestRetrieveObject(t *testing.T) {
	ctx := NewTestContext(t)
	type X struct {
		I int
		S string
	}
	x, id, err := CacheObject(ctx, "foo", "1", func() (X, error) {
		return X{42, "foo"}, nil
	})
	require.NoError(t, err)
	require.Equal(t, x, X{42, "foo"})
	require.NotEmpty(t, id)

	x2, err := RetrieveObject[X](ctx, id)
	require.NoError(t, err)
	require.Equal(t, x2, X{42, "foo"})
}

func TestRetrieveObject_InvalidID(t *testing.T) {
	ctx := NewTestContext(t)
	type X struct{}

	_, err := RetrieveObject[X](ctx, "coverage/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "parts cannot be empty")

	_, err = RetrieveObject[X](ctx, "invalid")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid cached ID format")

	_, err = RetrieveObject[X](ctx, "../invalid")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid cached ID (not local)")
}

// TestCachePurgeStaged verifies that an evicted entry is both staged and actually removed.
func TestCachePurgeStaged(t *testing.T) {
	tempDir := t.TempDir()
	c, err := newTestCache(t, tempDir, 10<<10, time.Now)
	require.NoError(t, err)

	// Create an entry that fills the cache, then release it so that it becomes evictable.
	oldDir, err := c.Create("old", "1", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "f"), bytes.Repeat([]byte{'a'}, 20<<10))
	})
	require.NoError(t, err)
	c.Release(oldDir)

	newDir, err := c.Create("build", "target", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "out"), []byte("ok"))
	})
	require.NoError(t, err)
	c.Release(newDir)

	// The old entry is evicted (phase 1) and the staged dir is removed (phase 2).
	require.NotContains(t, c.entries, oldDir)
	require.False(t, osutil.IsExist(oldDir))
	left, err := filepath.Glob(filepath.Join(c.trashDir(), "*"))
	require.NoError(t, err)
	require.Empty(t, left)
	require.Contains(t, c.entries, newDir)
}

func TestCacheInitStagedTrash(t *testing.T) {
	tempDir := t.TempDir()
	c, err := newTestCache(t, tempDir, 1<<40, time.Now)
	require.NoError(t, err)

	dir, err := c.Create("build", "1", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "out"), []byte("hello"))
	})
	require.NoError(t, err)
	c.Release(dir)

	// Simulate an interrupted eviction: the entry was staged for removal, but the process
	// was terminated before it was removed. The staged dir still holds a valid meta file.
	staged := filepath.Join(c.trashDir(), "1-12345")
	require.NoError(t, osutil.MkdirAll(c.trashDir()))
	require.NoError(t, os.Rename(dir, staged))

	// The trash dir itself has no meta file, so init removes it with all of its contents
	// instead of ingesting the staged entry as a valid one.
	c2, err := newTestCache(t, tempDir, 1<<40, time.Now)
	require.NoError(t, err)
	require.False(t, osutil.IsExist(c2.trashDir()))
	require.Equal(t, uint64(0), c2.currentSize)
	require.Empty(t, c2.entries)
}

// TestCacheTmpTyp verifies that "tmp" is a usable entry type, i.e. that entries don't collide
// with the dir that holds temp dirs and the entries staged for removal.
func TestCacheTmpTyp(t *testing.T) {
	tempDir := t.TempDir()
	c, err := newTestCache(t, tempDir, 1<<40, time.Now)
	require.NoError(t, err)

	dir, err := c.Create("tmp", "1", func(dir string) error {
		return osutil.WriteFile(filepath.Join(dir, "out"), []byte("hello"))
	})
	require.NoError(t, err)
	c.Release(dir)

	// The entry must survive a restart.
	c2, err := newTestCache(t, tempDir, 1<<40, time.Now)
	require.NoError(t, err)
	require.Contains(t, c2.entries, dir)
	data, err := os.ReadFile(filepath.Join(dir, "out"))
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), data)
}
