// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/report"
)

var (
	flagOS        = flag.String("os", runtime.GOOS, "target os")
	flagKernelSrc = flag.String("kernel_src", "", "path to kernel sources")
	flagKernelObj = flag.String("kernel_obj", "", "path to kernel build/obj dir")
	flagReport    = flag.Bool("report", false, "extract report from the log")
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "usage: syz-symbolize [flags] kernel_log_file\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	reporter, err := report.NewReporter(*flagOS, *flagKernelSrc, *flagKernelObj, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create reporter: %v\n", err)
		os.Exit(1)
	}
	text, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open input file: %v\n", err)
		os.Exit(1)
	}
	if *flagReport {
		desc, text, _, _ := reporter.Parse(text)
		text, err = reporter.Symbolize(text)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to symbolize: %v\n", err)
			os.Exit(1)
		}
		guiltyFile := reporter.ExtractGuiltyFile(text)
		fmt.Printf("%v\n\n", desc)
		os.Stdout.Write(text)
		fmt.Printf("\n")
		fmt.Printf("guilty file: %v\n", guiltyFile)
		if guiltyFile != "" {
			maintainers, err := reporter.GetMaintainers(guiltyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to get maintainers: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("maintainers: %v\n", maintainers)
		}
	} else {
		if console := reporter.ExtractConsoleOutput(text); len(console) != 0 {
			text = console
		}
		text, err = reporter.Symbolize(text)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to symbolize: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(text)
	}
}
