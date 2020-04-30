// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cmdprof simplifies cpu/memory profiling for command line tools. Use as:
//	flag.Parse()
//	defer cmdprof.Install()()
package cmdprof

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
)

var (
	flagCPUProfile = flag.String("cpuprofile", "", "write CPU profile to this file")
	flagMEMProfile = flag.String("memprofile", "", "write memory profile to this file")
)

func Install() func() {
	res := func() {}
	failf := func(msg string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, msg+"\n", args...)
		os.Exit(1)
	}
	if *flagCPUProfile != "" {
		f, err := os.Create(*flagCPUProfile)
		if err != nil {
			failf("failed to create cpuprofile file: %v", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			failf("failed to start cpu profile: %v", err)
		}
		res = func() {
			pprof.StopCPUProfile()
			f.Close()
		}
	}
	if *flagMEMProfile != "" {
		prev := res
		res = func() {
			prev()
			f, err := os.Create(*flagMEMProfile)
			if err != nil {
				failf("failed to create memprofile file: %v", err)
			}
			defer f.Close()
			runtime.GC()
			if err := pprof.WriteHeapProfile(f); err != nil {
				failf("failed to write mem profile: %v", err)
			}
		}
	}
	return res
}
