// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fileutil

import (
	"bytes"
	"io/ioutil"
	"os"
	"strconv"
	"sync"
	"testing"
	"path/filepath"
)

func TestProcessTempDir(t *testing.T) {
	for try := 0; try < 10; try++ {
		func() {
			tmp, err := ioutil.TempDir("", "syz")
			if err != nil {
				t.Fatalf("failed to create a temp dir: %v", err)
			}
			defer os.RemoveAll(tmp)
			const P = 16
			// Pre-create half of the instances with stale pid.
			var dirs []string
			for i := 0; i < P/2; i++ {
				dir, idx, err := ProcessTempDir(tmp)
				if err != nil {
					t.Fatalf("failed to create process temp dir")
				}
				if idx != i {
					t.Fatalf("unexpected index: want %v, got %v", i, idx)
				}
				dirs = append(dirs, dir)
			}
			for _, dir := range dirs {
				if err := ioutil.WriteFile(filepath.Join(dir, ".pid"), []byte(strconv.Itoa(999999999)), 0600); err != nil {
					t.Fatalf("failed to write pid file: %v", err)
				}
			}
			// Now request a bunch of instances concurrently.
			done := make(chan bool)
			indices := make(map[int]bool)
			var mu sync.Mutex
			for p := 0; p < P; p++ {
				go func() {
					defer func() {
						done <- true
					}()
					dir, idx, err := ProcessTempDir(tmp)
					if err != nil {
						t.Fatalf("failed to create process temp dir")
					}
					mu.Lock()
					present := indices[idx]
					indices[idx] = true
					mu.Unlock()
					if present {
						t.Fatalf("duplicate index %v", idx)
					}
					data := []byte(strconv.Itoa(idx))
					if err := ioutil.WriteFile(filepath.Join(dir, "data"), data, 0600); err != nil {
						t.Fatalf("failed to write data file: %v", err)
					}
					data1, err := ioutil.ReadFile(filepath.Join(dir, "data"))
					if err != nil {
						t.Fatalf("failed to read data file: %v", err)
					}
					if bytes.Compare(data, data1) != 0 {
						t.Fatalf("corrupted data file")
					}
				}()
			}
			for p := 0; p < P; p++ {
				<-done
			}
		}()
	}
}
