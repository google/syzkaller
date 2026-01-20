// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
)

// Cache maintains on-disk cache with directories with arbitrary contents (kernel checkouts, builds, etc).
// Create method is used to either create a new directory, if it's not cached yet, or returns a previously
// cached directory. Old unused directories are incrementally removed if the total disk usage grows
// over the specified limit.
type Cache struct {
	dir         string
	maxSize     uint64
	timeNow     func() time.Time
	t           *testing.T
	mu          sync.Mutex
	currentSize uint64
	entries     map[string]*cacheEntry
}

type cacheEntry struct {
	dir        string
	size       uint64
	usageCount int
	lastUsed   time.Time
}

func NewCache(dir string, maxSize uint64) (*Cache, error) {
	return newTestCache(nil, dir, maxSize, time.Now)
}

func newTestCache(t *testing.T, dir string, maxSize uint64, timeNow func() time.Time) (*Cache, error) {
	if dir == "" {
		return nil, fmt.Errorf("cache workdir is empty")
	}
	c := &Cache{
		dir:     osutil.Abs(dir),
		maxSize: maxSize,
		timeNow: timeNow,
		t:       t,
		entries: make(map[string]*cacheEntry),
	}
	if err := c.init(); err != nil {
		return nil, err
	}
	return c, nil
}

// Create creates/returns a cached directory with contents created by the populate callback.
// The populate callback receives a dir it needs to populate with cached files.
// The typ must be a short descriptive name of the contents (e.g. "build", "source", etc).
// The desc is used to identify cached entries and must fully describe the cached contents
// (the second invocation with the same typ+desc will return dir created by the first
// invocation with the same typ+desc).
func (c *Cache) Create(typ, desc string, populate func(string) error) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Note: we don't populate a temp dir and then atomically rename it to the final destination,
	// because at least kernel builds encode the current path in debug info/compile commands,
	// so moving the dir later would break all that. Instead we rely on the presence of the meta file
	// to denote valid cache entries. Modification time of the file says when it was last used.
	id := hash.String(desc)
	dir := filepath.Join(c.dir, typ, id)
	metaFile := filepath.Join(dir, cacheMetaFile)
	if c.entries[dir] == nil {
		os.RemoveAll(dir)
		if err := osutil.MkdirAll(dir); err != nil {
			return "", err
		}
		if err := populate(dir); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
		size, err := osutil.DiskUsage(dir)
		if err != nil {
			return "", err
		}
		meta := cacheMeta{
			Description: desc,
			DiskUsage:   size,
		}
		if err := osutil.WriteJSON(metaFile, meta); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
		c.entries[dir] = &cacheEntry{
			dir:  dir,
			size: size,
		}
		c.currentSize += size
		c.logf("created entry %v, size %v, current size %v", dir, size, c.currentSize)
	}
	// Note the entry was used now.
	now := c.timeNow()
	if err := os.Chtimes(metaFile, now, now); err != nil {
		return "", err
	}
	entry := c.entries[dir]
	entry.usageCount++
	entry.lastUsed = now
	c.logf("using entry %v, usage count %v", dir, entry.usageCount)
	if err := c.purge(); err != nil {
		entry.usageCount--
		return "", err
	}
	return dir, nil
}

func cacheCreateObject[T any](c *Cache, typ, desc string, populate func() (T, error)) (string, T, error) {
	const filename = "object"
	dir, err := c.Create(typ, desc, func(dir string) error {
		v, err := populate()
		if err != nil {
			return err
		}
		return osutil.WriteJSON(filepath.Join(dir, filename), v)
	})
	if err != nil {
		var res T
		return "", res, err
	}
	res, err := osutil.ReadJSON[T](filepath.Join(dir, filename))
	return dir, res, err
}

// Release must be called for every directory returned by Create method when the directory is not used anymore.
func (c *Cache) Release(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[dir]
	entry.usageCount--
	c.logf("release entry %v, usage count %v", dir, entry.usageCount)
	if entry.usageCount < 0 {
		panic("negative usageCount")
	}
}

// TempDir creates a new temp dir.
// The temp dir is within the cache, but won't have the metadata file,
// so it will be removed on the next start (if not removed earlier).
func (c *Cache) TempDir() (string, error) {
	tmpDir := filepath.Join(c.dir, "tmp")
	osutil.MkdirAll(tmpDir)
	return os.MkdirTemp(tmpDir, "tmp")
}

// init reads the cached dirs (disk usage, last use time) from disk when the cache is created.
func (c *Cache) init() error {
	dirs, err := filepath.Glob(filepath.Join(c.dir, "*", "*"))
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		metaFile := filepath.Join(dir, cacheMetaFile)
		data, err := os.ReadFile(metaFile)
		if err != nil {
			if os.IsNotExist(err) {
				// Incomplete cache dir.
				if err := osutil.RemoveAll(dir); err != nil {
					return err
				}
				continue
			}
			return err
		}
		var meta cacheMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			// Assume the old format that contained just the description.
			// This code can be removed after 2027-06-01,
			// and the code above can use osutil.ReadJSON.
			size, err := osutil.DiskUsage(dir)
			if err != nil {
				return err
			}
			meta.Description = string(data)
			meta.DiskUsage = size
			if err := osutil.WriteJSON(metaFile, meta); err != nil {
				return err
			}
		}
		stat, err := os.Stat(metaFile)
		if err != nil {
			return err
		}
		c.entries[dir] = &cacheEntry{
			dir:      dir,
			size:     meta.DiskUsage,
			lastUsed: stat.ModTime(),
		}
		c.currentSize += meta.DiskUsage
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.purge()
}

// purge removes oldest unused directories if the cache is over maxSize.
func (c *Cache) purge() error {
	if c.mu.TryLock() {
		panic("c.mu is not locked")
	}
	if c.currentSize < c.maxSize {
		return nil
	}
	list := slices.Collect(maps.Values(c.entries))
	slices.SortFunc(list, func(a, b *cacheEntry) int {
		if a.usageCount != b.usageCount {
			return a.usageCount - b.usageCount
		}
		return a.lastUsed.Compare(b.lastUsed)
	})
	for _, entry := range list {
		if entry.usageCount != 0 || c.currentSize < c.maxSize {
			break
		}
		if err := os.RemoveAll(entry.dir); err != nil {
			return err
		}
		delete(c.entries, entry.dir)
		if c.currentSize < entry.size {
			panic(fmt.Sprintf("negative currentSize: %v %v", c.currentSize, entry.size))
		}
		c.currentSize -= entry.size
	}
	return nil
}

func (c *Cache) logf(msg string, args ...any) {
	if c.t != nil {
		c.t.Logf("cache: "+msg, args...)
	}
}

type cacheMeta struct {
	Description string
	DiskUsage   uint64
}

const cacheMetaFile = "aflow-meta"
