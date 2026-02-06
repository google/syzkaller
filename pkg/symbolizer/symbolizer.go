// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"os"
	"sync"

	"github.com/google/syzkaller/sys/targets"
)

type Frame struct {
	PC     uint64
	Func   string
	File   string
	Line   int
	Column int
	Inline bool
}

type Symbolizer interface {
	Symbolize(bin string, pcs ...uint64) ([]Frame, error)
	Close()
	Name() string
}

func Make(target *targets.Target, bin string) (Symbolizer, error) {
	if target != nil && target.Arch == targets.AMD64 && bin != "" {
		cacheMu.Lock()
		defer cacheMu.Unlock()
		if entry, ok := cache[bin]; ok {
			if info, err := os.Stat(bin); err == nil && os.SameFile(info, entry.info) &&
				info.ModTime().Equal(entry.info.ModTime()) {
				return &sharedSymbolizer{entry.sym}, nil
			}
			delete(cache, bin)
			// We can't close the old symbolizer easily as it might be in use.
			// Rely on GC or leak (it's small number of kernels usually).
			// Ideally we should Close() it when refcount drops, but that's complex.
			// For now, let's assume valid kernels are few.
		}

		if s, err := newELFSymbolizer(bin); err == nil {
			if info, err := os.Stat(bin); err == nil {
				cache[bin] = &cachedSym{s, info}
				return &sharedSymbolizer{s}, nil
			}
			return s, nil
		}
	}
	return &addr2Line{target: target}, nil
}

var (
	cacheMu sync.Mutex
	cache   = make(map[string]*cachedSym)
)

type cachedSym struct {
	sym  Symbolizer
	info os.FileInfo
}

type sharedSymbolizer struct {
	Symbolizer
}

func (s *sharedSymbolizer) Close() {}
