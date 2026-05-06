// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/google/syzkaller/pkg/codesearch"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/tools/clang/codesearch"
)

func main() {
	var (
		flagDatabase  = flag.String("database", "", "path to input/output database file (mandatory)")
		flagKernelSrc = flag.String("kernel-src", "", "path to kernel source directory (mandatory)")
		flagKernelObj = flag.String("kernel-obj", "", "path to kernel build directory (mandatory)")
	)
	defer tool.Init()()
	if len(flag.Args()) == 0 || *flagDatabase == "" || *flagKernelSrc == "" || *flagKernelObj == "" {
		printUsageAndExit()
	}
	cmd, args := flag.Args()[0], flag.Args()[1:]
	if cmd == "index" {
		if len(args) != 0 {
			printUsageAndExit()
		}
		cfg := &clangtool.Config{
			Tool:       clangtoolimpl.Tool,
			KernelSrc:  *flagKernelSrc,
			KernelObj:  *flagKernelObj,
			CacheFile:  *flagDatabase,
			DebugTrace: os.Stderr,
		}

		if _, err := clangtool.Run[codesearch.Database](cfg); err != nil {
			tool.Fail(err)
		}
		return
	}
	index, err := codesearch.NewIndex(*flagDatabase, []string{*flagKernelSrc, *flagKernelObj})
	if err != nil {
		tool.Fail(err)
	}
	res, err := index.Command(cmd, args)
	if err != nil {
		tool.Fail(err)
	}
	os.Stdout.WriteString(res)
}

func printUsageAndExit() {
	fmt.Printf(`syz-codesearch usage:
syz-codesearch [flags] command [command arguments]
commands and their arguments:
`)
	for _, cmd := range codesearch.Commands {
		fmt.Printf("  - %v [%v args]\n", cmd.Name, cmd.NArgs)
	}
	fmt.Printf("\nflags:\n")
	flag.PrintDefaults()
	os.Exit(1)
}
