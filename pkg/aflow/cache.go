// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
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
			Version:     currentCacheVersion,
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
	c.purge()
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
	tmpDir := c.tmpDir()
	osutil.MkdirAll(tmpDir)
	return os.MkdirTemp(tmpDir, "tmp")
}

// tmpDir holds temp dirs and the entries staged for removal, but never cache entries:
// init removes its contents on the next start.
func (c *Cache) tmpDir() string {
	return filepath.Join(c.dir, "tmp")
}

// trashDir returns the dir where purge stages evicted entries before removing them.
// It's nested one level deeper than cache entries on purpose, see the glob in init.
func (c *Cache) trashDir() string {
	return filepath.Join(c.tmpDir(), "trash")
}

// removeAll removes the dir and reports failures. A failure is not fatal, but it does mean that
// the disk space is not reclaimed until the next start: a dir staged for removal is removed by
// init together with the whole trash dir, while an entry removed in place (the purge fallback
// below) still holds its meta file, so init just picks it up as a valid entry again.
func (c *Cache) removeAll(dir string) {
	if err := osutil.RemoveAll(dir); err != nil {
		log.Errorf("aflow cache: failed to remove %v: %v", dir, err)
	}
}

// init reads the cached dirs (disk usage, last use time) from disk when the cache is created.
func (c *Cache) init() error {
	// Note: the glob matches exactly two levels, and that's what makes the trash dir work.
	// The entries staged for removal sit one level deeper and still hold their meta files,
	// so walking the tree recursively here would resurrect all of them as valid entries.
	dirs, err := filepath.Glob(filepath.Join(c.dir, "*", "*"))
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		metaFile := filepath.Join(dir, cacheMetaFile)
		data, err := os.ReadFile(metaFile)
		if err != nil {
			if os.IsNotExist(err) {
				// Either an incomplete cache dir, or a leftover of the previous run:
				// a temp dir, or the trash dir with the entries that purge staged for
				// removal but did not manage to remove.
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
	c.purge()
	return nil
}

// purge removes oldest unused directories if the cache is over maxSize.
// c.mu must be held when called; purge temporarily unlocks c.mu while removing staged files.
// Note: returning the staged dirs and letting the caller remove them after releasing the lock
// would be cleaner, but it does not work here: Create calls purge with a pending
// defer c.mu.Unlock(), so it cannot release the lock before it returns, and the removal would
// end up under the lock again. Restructuring Create to avoid that is not worth it for now.
func (c *Cache) purge() {
	if c.mu.TryLock() {
		panic("c.mu is not locked")
	}
	if c.currentSize < c.maxSize {
		return
	}
	unused := make([]*cacheEntry, 0, len(c.entries))
	for _, entry := range c.entries {
		if entry.usageCount == 0 {
			unused = append(unused, entry)
		}
	}
	if len(unused) == 0 {
		return
	}
	slices.SortFunc(unused, func(a, b *cacheEntry) int {
		return a.lastUsed.Compare(b.lastUsed)
	})
	trashDir := c.trashDir()
	_ = osutil.MkdirAll(trashDir)
	var staged []string
	for _, entry := range unused {
		if c.currentSize < c.maxSize {
			break
		}
		// Phase 1: atomically move the dir to a staging path under the lock, so that
		// a concurrent Create can immediately re-populate entry.dir without colliding
		// with our removal (re-populating a dir starts with its own RemoveAll/MkdirAll).
		// The timestamp disambiguates an entry re-evicted while its predecessor is still staged.
		dst := filepath.Join(trashDir, fmt.Sprintf("%v-%v", filepath.Base(entry.dir), time.Now().UnixNano()))
		if err := os.Rename(entry.dir, dst); err != nil {
			// Staging failed, fall back to removing the dir in place under the lock.
			c.removeAll(entry.dir)
		} else {
			staged = append(staged, dst)
		}
		delete(c.entries, entry.dir)
		if c.currentSize < entry.size {
			panic(fmt.Sprintf("negative currentSize: %v %v", c.currentSize, entry.size))
		}
		c.currentSize -= entry.size
	}
	// Phase 2: remove the staged dirs with the lock released, this can be very slow
	// for large dirs and does not need to block concurrent cache users.
	if len(staged) > 0 {
		c.mu.Unlock()
		for _, dir := range staged {
			c.removeAll(dir)
		}
		c.mu.Lock()
	}
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
