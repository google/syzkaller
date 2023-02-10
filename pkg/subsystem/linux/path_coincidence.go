// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"io/fs"
	"regexp"
	"runtime"
	"sync"

	"github.com/google/syzkaller/pkg/subsystem"
)

func BuildCoincidenceMatrix(root fs.FS, list []*subsystem.Subsystem,
	excludeRe *regexp.Regexp) (*CoincidenceMatrix, error) {
	// Create a matcher.
	matcher := subsystem.MakePathMatcher(list)
	chPaths, chResult := extractSubsystems(matcher)
	// The final consumer goroutine.
	cm := MakeCoincidenceMatrix()
	ready := make(chan struct{})
	go func() {
		for items := range chResult {
			cm.Record(items...)
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
	return cm, err
}

var (
	includePathRe = regexp.MustCompile(`(?:/|\.(?:c|h|S))$`)
)

func extractSubsystems(matcher *subsystem.PathMatcher) (chan<- string, <-chan []*subsystem.Subsystem) {
	procs := runtime.NumCPU()
	paths, output := make(chan string, procs), make(chan []*subsystem.Subsystem, procs)
	var wg sync.WaitGroup
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range paths {
				output <- matcher.Match(path)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(output)
	}()
	return paths, output
}
