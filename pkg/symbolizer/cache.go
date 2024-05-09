// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"strings"
	"sync"
)

// Cache caches symbolization results from Symbolizer in a thread-safe way.
type Cache struct {
	mu    sync.RWMutex
	cache map[cacheKey]cacheVal
}

type cacheKey struct {
	bin string
	pc  uint64
}

type cacheVal struct {
	frames []Frame
	err    error
}

func (c *Cache) Symbolize(inner func(string, uint64) ([]Frame, error), bin string, pc uint64) ([]Frame, error) {
	key := cacheKey{bin, pc}
	c.mu.RLock()
	val, ok := c.cache[key]
	c.mu.RUnlock()
	if ok {
		return val.frames, val.err
	}
	frames, err := inner(bin, pc)
	c.mu.Lock()
	if c.cache == nil {
		c.cache = make(map[cacheKey]cacheVal)
	}
	c.cache[key] = cacheVal{frames, err}
	c.mu.Unlock()
	return frames, err
}

// Interner allows to intern/deduplicate strings.
// Interner.Do semantically returns the same string, but physically it will point
// to an existing string with the same contents (if there was one passed to Do in the past).
// Interned strings are also "cloned", that is, if the passed string points to a large
// buffer, it won't after interning (and won't prevent GC'ing of the large buffer).
// The type is not thread-safe.
type Interner struct {
	m sync.Map
}

func (in *Interner) Do(s string) string {
	if interned, ok := in.m.Load(s); ok {
		return interned.(string)
	}
	s = strings.Clone(s)
	in.m.Store(s, s)
	return s
}
