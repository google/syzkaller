// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package tool

import (
	"os"
	"runtime"
	"runtime/pprof"
)

// installProfiling simplifies cpu/memory profiling for command line tools.
func installProfiling(cpuprof, memprof string) func() {
	res := func() {}
	if cpuprof != "" {
		f, err := os.Create(cpuprof)
		if err != nil {
			Failf("failed to create cpuprofile file: %v", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			Failf("failed to start cpu profile: %v", err)
		}
		res = func() {
			pprof.StopCPUProfile()
			f.Close()
		}
	}
	if memprof != "" {
		prev := res
		res = func() {
			prev()
			f, err := os.Create(memprof)
			if err != nil {
				Failf("failed to create memprofile file: %v", err)
			}
			defer f.Close()
			runtime.GC()
			if err := pprof.WriteHeapProfile(f); err != nil {
				Failf("failed to write mem profile: %v", err)
			}
		}
	}
	return res
}
