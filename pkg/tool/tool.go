// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package tool contains various helper utilitites useful for implementation of command line tools.
package tool

import (
	"flag"
	"fmt"
	"os"
)

// Init handles common tasks for command line tools:
//  - invokes flag.Parse
//  - adds support for optional flags (see OptionalFlags)
//  - adds support for cpu/mem profiling (-cpuprofile/memprofile flags)
// Use as defer tool.Init()().
func Init() func() {
	flagCPUProfile := flag.String("cpuprofile", "", "write CPU profile to this file")
	flagMEMProfile := flag.String("memprofile", "", "write memory profile to this file")
	if err := ParseFlags(flag.CommandLine, os.Args[1:]); err != nil {
		Fail(err)
	}
	return installProfiling(*flagCPUProfile, *flagMEMProfile)
}

func Failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func Fail(err error) {
	Failf("%v", err)
}
