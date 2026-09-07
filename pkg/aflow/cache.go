// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
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
	"golang.org/x/sync/singleflight"
)

// Cache maintains on-disk cache with directories with arbitrary contents (kernel checkouts, builds, etc).
// Create method is used to either create a new directory, if it's not cached yet, or returns a previously
// cached directory. Old unused directories are incrementally removed if the total disk usage grows
// over the specified limit.
type Cache struct {
	dir     string
	maxSize uint64
	timeNow func() time.Time
	t       *testing.T
	// flight coalesces concurrent population of the same cache entry.
	flight      singleflight.Group
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
	// Note: we don't populate a temp dir and then atomically rename it to the final destination,
	// because at least kernel builds encode the current path in debug info/compile commands,
	// so moving the dir later would break all that. Instead we rely on the presence of the meta file
	// to denote valid cache entries. Modification time of the file says when it was last used.
	id := hash.String(desc)
	dir := filepath.Join(c.dir, typ, id)
	metaFile := filepath.Join(dir, cacheMetaFile)
	// Concurrent requests for the same entry are coalesced and share the result, including errors.
	// Failures are never cached (no entry is created), so the next Create will populate the dir
	// again, and the callers that expect transient failures (e.g. the LLM agent) retry themselves.
	// This is better than letting every caller re-run a failed multi-minute operation in turn.
	if _, err, _ := c.flight.Do(dir, func() (any, error) {
		return nil, c.populateEntry(dir, metaFile, desc, populate)
	}); err != nil {
		return "", err
	}
	if err := c.useEntry(dir, metaFile); err != nil {
		return "", err
	}
	return dir, nil
}

// populateEntry creates the cache entry for the dir, unless it's already cached.
// It must be called under c.flight to avoid concurrent population of the same dir.
func (c *Cache) populateEntry(dir, metaFile, desc string, populate func(string) error) error {
	c.mu.Lock()
	cached := c.entries[dir] != nil
	c.mu.Unlock()
	if cached {
		return nil
	}
	// Note: the entry is not accounted in currentSize until it's fully populated
	// (we don't know its size in advance), so the cache may temporarily grow over maxSize.
	// The extra space is reclaimed by the purge that follows the population.
	size, err := c.populateDir(dir, metaFile, desc, populate)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[dir] = &cacheEntry{
		dir:  dir,
		size: size,
		// Set lastUsed right away, otherwise the entry looks like the oldest one
		// and may be purged before the caller accounts its use.
		lastUsed: c.timeNow(),
	}
	c.currentSize += size
	c.logf("created entry %v, size %v, current size %v", dir, size, c.currentSize)
	return nil
}

// useEntry accounts one more use of the cached dir.
func (c *Cache) useEntry(dir, metaFile string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[dir]
	if entry == nil {
		// A concurrent Create has purged the entry before we accounted its use.
		// The entry is the most recently used one, so this means that the cache is over the limit
		// and all of the older entries are still in use.
		return fmt.Errorf("cache entry %v was purged before use, the cache is too small", dir)
	}
	now := c.timeNow()
	if err := os.Chtimes(metaFile, now, now); err != nil {
		return err
	}
	entry.usageCount++
	entry.lastUsed = now
	c.logf("using entry %v, usage count %v", dir, entry.usageCount)
	if err := c.purge(); err != nil {
		entry.usageCount--
		return err
	}
	return nil
}

func (c *Cache) populateDir(dir, metaFile, desc string, populate func(string) error) (uint64, error) {
	os.RemoveAll(dir)
	if err := osutil.MkdirAll(dir); err != nil {
		return 0, err
	}
	if err := populate(dir); err != nil {
		os.RemoveAll(dir)
		return 0, err
	}
	size, err := osutil.DiskUsage(dir)
	if err != nil {
		os.RemoveAll(dir)
		return 0, err
	}
	meta := cacheMeta{
		Version:     currentCacheVersion,
		Description: desc,
		DiskUsage:   size,
	}
	if err := osutil.WriteJSON(metaFile, meta); err != nil {
		os.RemoveAll(dir)
		return 0, err
	}
	return size, nil
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

func cacheReadObject[T any](c *Cache, typ, id, filename string) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dir := filepath.Join(c.dir, typ, id)
	entry := c.entries[dir]
	if entry == nil {
		var res T
		return res, fmt.Errorf("cache entry not found")
	}
	now := c.timeNow()
	metaFile := filepath.Join(dir, cacheMetaFile)
	// If we can't update time, just proceed with reading.
	_ = os.Chtimes(metaFile, now, now)
	entry.lastUsed = now
	return osutil.ReadJSON[T](filepath.Join(dir, filename))
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
		meta, err := osutil.ParseJSON[cacheMeta](data)
		if err != nil || meta.Version != currentCacheVersion {
			// An older metadata format, update it to the current version.
			size, err := osutil.DiskUsage(dir)
			if err != nil {
				return err
			}
			// Assume meta.Description is present.
			meta.Version = currentCacheVersion
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
		// Note: the removal must happen under c.mu, despite it may be slow for large dirs.
		// Otherwise a concurrent Create may start populating the dir (populateDir begins
		// with its own RemoveAll/MkdirAll) while we are still deleting it.
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
	Version     int
	Description string
	DiskUsage   uint64
}

const (
	cacheMetaFile       = "aflow-meta"
	currentCacheVersion = 1
)
