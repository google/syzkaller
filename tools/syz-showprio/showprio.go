// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-showprio visualizes the call to call priorities from the prog package.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

var (
	flagOS     = flag.String("os", runtime.GOOS, "target os")
	flagArch   = flag.String("arch", runtime.GOARCH, "target arch")
	flagEnable = flag.String("enable", "", "comma-separated list of enabled syscalls")
	flagCorpus = flag.String("corpus", "", "name of the corpus file")
)

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	if *flagEnable == "" {
		fmt.Fprintf(os.Stderr, "no syscalls enabled")
		os.Exit(1)
	}
	enabled := strings.Split(*flagEnable, ",")
	_, err = mgrconfig.ParseEnabledSyscalls(target, enabled, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse enabled syscalls: %v", err)
		os.Exit(1)
	}
	corpus, err := db.ReadCorpus(*flagCorpus, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read corpus: %v", err)
		os.Exit(1)
	}
	showPriorities(enabled, target.CalculatePriorities(corpus), target)
}

func showPriorities(calls []string, prios [][]float32, target *prog.Target) {
	printLine(append([]string{"CALLS"}, calls...))
	for _, callRow := range calls {
		line := []string{callRow}
		for _, callCol := range calls {
			val := prios[target.SyscallMap[callRow].ID][target.SyscallMap[callCol].ID]
			line = append(line, fmt.Sprintf("%.2f", val))
		}
		printLine(line)
	}
}

func printLine(values []string) {
	fmt.Printf("|")
	for _, val := range values {
		fmt.Printf("%-20v|", val)
	}
	fmt.Printf("\n")
}
