// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func TestProcessTempDir(t *testing.T) {
	for range 10 {
		func() {
			tmp := t.TempDir()
			const P = 16
			// Pre-create half of the instances with stale pid.
			var dirs []string
			for range P / 2 {
				dir, err := ProcessTempDir(tmp)
				if err != nil {
					t.Fatalf("failed to create process temp dir")
				}
				dirs = append(dirs, dir)
			}
			for _, dir := range dirs {
				if err := WriteFile(filepath.Join(dir, ".pid"), []byte(strconv.Itoa(999999999))); err != nil {
					t.Fatalf("failed to write pid file: %v", err)
				}
			}
			// Now request a bunch of instances concurrently.
			done := make(chan error)
			allDirs := make(map[string]bool)
			var mu sync.Mutex
			for range P {
				go func() {
					dir, err := ProcessTempDir(tmp)
					if err != nil {
						done <- fmt.Errorf("failed to create temp dir: %w", err)
						return
					}
					mu.Lock()
					present := allDirs[dir]
					allDirs[dir] = true
					mu.Unlock()
					if present {
						done <- fmt.Errorf("duplicate dir %v", dir)
						return
					}
					done <- nil
				}()
			}
			for range P {
				if err := <-done; err != nil {
					t.Error(err)
				}
			}
		}()
	}
}
