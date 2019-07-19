// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	hostOS := or(os.Getenv("HOSTOS"), runtime.GOOS)
	hostArch := or(os.Getenv("HOSTARCH"), runtime.GOARCH)
	targetOS := or(os.Getenv("TARGETOS"), hostOS)
	targetArch := or(os.Getenv("TARGETARCH"), hostArch)
	targetVMArch := or(os.Getenv("TARGETVMARCH"), targetArch)
	target := targets.Get(targetOS, targetArch)
	if target == nil {
		fmt.Printf("unknown target %v/%v\n", targetOS, targetArch)
		os.Exit(1)
	}
	type Var struct {
		Name string
		Val  string
	}
	parallelism := runtime.NumCPU()
	if mem := osutil.SystemMemorySize(); mem != 0 {
		// Ensure that we have at least 1GB per Makefile job.
		// Go compiler/linker can consume significant amount of memory
		// (observed to consume at least 600MB). See #1276 for context.
		memLimit := int(mem / (1 << 30))
		if parallelism > memLimit {
			parallelism = memLimit
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
		{"ADDCFLAGS", strings.Join(target.CrossCFlags, " ")},
		{"NCORES", strconv.Itoa(parallelism)},
		{"EXE", target.ExeExtension},
		{"NATIVEBUILDOS", target.BuildOS},
	}
	if targetOS != runtime.GOOS {
		if _, err := exec.LookPath(target.CCompiler); err != nil {
			vars = append(vars, Var{"NO_CROSS_COMPILER", "yes"})
		}
	}
	for _, v := range vars {
		fmt.Printf("export %v=%v\\n", v.Name, v.Val)
	}
}

func or(s1, s2 string) string {
	if s1 != "" {
		return s1
	}
	return s2
}
