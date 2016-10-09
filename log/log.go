// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// log package provides functionality similar to standard log package with some extensions:
//  - verbosity levels
//  - global verbosity setting that can be used by multiple packages
//  - ability to disable all output
//  - ability to cache recent output in memory
package log

import (
	"bytes"
	"flag"
	"fmt"
	golog "log"
	"sync"
)

var (
	flagV        = flag.Int("v", 0, "verbosity")
	mu           sync.Mutex
	disabled     bool
	cacheMem     int
	cacheMaxMem  int
	cachePos     int
	cacheEntries []string
)

// EnableCaching enables in memory caching of log output.
// Caches up to maxLines, but no more than maxMem bytes.
// Cached output can later be queried with CachedOutput.
func EnableLogCaching(maxLines, maxMem int) {
	mu.Lock()
	defer mu.Unlock()
	if cacheEntries != nil {
		Fatalf("log caching is already enabled")
	}
	if maxLines < 1 || maxMem < 1 {
		panic("invalid maxLines/maxMem")
	}
	cacheMaxMem = maxMem
	cacheEntries = make([]string, maxLines)
}

// Retrieves cached log output.
func CachedLogOutput() string {
	mu.Lock()
	defer mu.Unlock()
	buf := new(bytes.Buffer)
	for i := range cacheEntries {
		pos := (cachePos + i) % len(cacheEntries)
		if cacheEntries[pos] == "" {
			continue
		}
		buf.WriteString(cacheEntries[pos])
		buf.Write([]byte{'\n'})
	}
	return buf.String()
}

func DisableLog() {
	mu.Lock()
	defer mu.Unlock()
	disabled = true
}

func Logf(v int, msg string, args ...interface{}) {
	mu.Lock()
	doLog := v <= *flagV && (v < 0 || !disabled)
	if cacheEntries != nil {
		cacheMem -= len(cacheEntries[cachePos])
		if cacheMem < 0 {
			panic("log cache size underflow")
		}
		cacheEntries[cachePos] = fmt.Sprintf(msg, args...)
		cacheMem += len(cacheEntries[cachePos])
		cachePos++
		if cachePos == len(cacheEntries) {
			cachePos = 0
		}
		for i := 0; i < len(cacheEntries)-1 && cacheMem > cacheMaxMem; i++ {
			pos := (cachePos + i) % len(cacheEntries)
			cacheMem -= len(cacheEntries[pos])
			cacheEntries[pos] = ""
		}
		if cacheMem < 0 {
			panic("log cache size underflow")
		}
	}
	mu.Unlock()

	if doLog {
		golog.Printf(msg, args...)
	}
}

func Fatalf(msg string, args ...interface{}) {
	golog.Fatalf(msg, args...)
}
