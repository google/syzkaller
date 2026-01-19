// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"io/fs"
	"regexp"
	"runtime"
	"sort"
	"sync"

	"github.com/google/syzkaller/pkg/subsystem"
)

func BuildCoincidenceMatrix(root fs.FS, list []*subsystem.Subsystem,
	excludeRe *regexp.Regexp) (*CoincidenceMatrix, *matrixDebugInfo, error) {
	// Create a matcher.
	matcher := subsystem.MakePathMatcher(list)
	chPaths, chResult := extractSubsystems(matcher)
	// The final consumer goroutine.
	cm := MakeCoincidenceMatrix()
	ready := make(chan struct{})
	debug := &matrixDebugInfo{files: map[*subsystem.Subsystem][]string{}}
	go func() {
		for item := range chResult {
			cm.Record(item.list...)
			for _, entity := range item.list {
				debug.files[entity] = append(debug.files[entity], item.path)
			}
		}
		ready <- struct{}{}
	}()
	// Source of data.
	err := fs.WalkDir(root, ".", func(path string, info fs.DirEntry, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !includePathRe.MatchString(path) ||
			(excludeRe != nil && excludeRe.MatchString(path)) {
			return nil
		}
		chPaths <- path
		return nil
	})
	close(chPaths)
	<-ready
	for _, list := range debug.files {
		sort.Strings(list)
	}
	return cm, debug, err
}

type matrixDebugInfo struct {
	files map[*subsystem.Subsystem][]string
}

var (
	includePathRe = regexp.MustCompile(`(?:/|\.(?:c|h|S))$`)
)

type extracted struct {
	path string
	list []*subsystem.Subsystem
}

func extractSubsystems(matcher *subsystem.PathMatcher) (chan<- string, <-chan extracted) {
	procs := runtime.NumCPU()
	paths, output := make(chan string, procs), make(chan extracted, procs)
	var wg sync.WaitGroup
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range paths {
				output <- extracted{
					path: path,
					list: matcher.Match(path),
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(output)
	}()
	return paths, output
}
