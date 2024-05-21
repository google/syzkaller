// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-make provides information required to build native code for the Makefile.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	vars, err := impl()
	if err != nil {
		fmt.Printf("export SYZERROR=%v\n", err)
		os.Exit(1)
	}
	for _, v := range vars {
		fmt.Printf("export %v=%v\\n", v.Name, v.Val)
	}
}

type Var struct {
	Name string
	Val  string
}

func impl() ([]Var, error) {
	hostOS := or(os.Getenv("HOSTOS"), runtime.GOOS)
	hostArch := or(os.Getenv("HOSTARCH"), runtime.GOARCH)
	targetOS := or(os.Getenv("TARGETOS"), hostOS)
	targetArch := or(os.Getenv("TARGETARCH"), hostArch)
	targetVMArch := or(os.Getenv("TARGETVMARCH"), targetArch)
	target := targets.Get(targetOS, targetArch)
	if target == nil {
		return nil, fmt.Errorf("unknown target %v/%v", targetOS, targetArch)
	}
	parallelism := runtime.NumCPU()
	if os.Getenv("CI") != "" {
		// Github actions VMs have 2 vCPUs (Standard_DS2_v2 class). So we don't get lots of speed up
		// from make parallelism, but we are getting memory oversubscription and duplicated work
		// because make invokes multiple go commands that potentially build same packages in parallel.
		// Go command itself parallelizes compiler and test invocations. So disable make parallelism
		// to avoid OOM kills.
		parallelism = 1
	}
	if runtime.GOOS == targets.OpenBSD {
		// Avoids too much concurrency on OpenBSD which can't handle this much.
		parallelism = 1
	}
	if mem := osutil.SystemMemorySize(); mem != 0 {
		// Ensure that we have at least 1GB per Go compiler/linker invocation.
		// Go compiler/linker can consume significant amount of memory
		// (observed to consume at least 600MB). See #1276 for context.
		// And we have parallelization both on make and on go levels,
		// this can severe oversubscribe RAM.
		// Note: the result can be significantly lower than the CPU number,
		// but this is fine because Go builds/tests are parallelized internally.
		memLimit := int(mem / (1 << 30))
		for parallelism > 1 && parallelism*parallelism > memLimit {
			parallelism--
		}
	}
	vars := []Var{
		{"BUILDOS", runtime.GOOS},
		{"NATIVEBUILDOS", target.BuildOS},
		{"HOSTOS", hostOS},
		{"HOSTARCH", hostArch},
		{"TARGETOS", targetOS},
		{"TARGETARCH", targetArch},
		{"TARGETVMARCH", targetVMArch},
		{"CC", target.CCompiler},
		{"CXX", target.CxxCompiler},
		{"ADDCFLAGS", strings.Join(target.CFlags, " ")},
		{"ADDCXXFLAGS", strings.Join(target.CxxFlags, " ")},
		{"NCORES", strconv.Itoa(parallelism)},
		{"EXE", target.ExeExtension},
		{"NATIVEBUILDOS", target.BuildOS},
		{"NO_CROSS_COMPILER", target.BrokenCompiler},
	}
	return vars, nil
}

func or(s1, s2 string) string {
	if s1 != "" {
		return s1
	}
	return s2
}
