// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/report"
)

var (
	flagKernelSrc = flag.String("kernel_src", "", "path to kernel sources")
	flagKernelObj = flag.String("kernel_obj", "", "path to kernel build dir")
	flagReport    = flag.Bool("report", false, "extract report from the log")
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "usage: syz-symbolize [flags] kernel_log_file\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *flagKernelSrc == "" {
		*flagKernelSrc = *flagKernelObj
	}
	text, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open input file: %v\n", err)
		os.Exit(1)
	}
	if *flagReport {
		desc, text, _, _ := report.Parse(text, nil)
		text, err = report.Symbolize(filepath.Join(*flagKernelObj, "vmlinux"), text, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to symbolize: %v\n", err)
			os.Exit(1)
		}
		guiltyFile := report.ExtractGuiltyFile(text)
		fmt.Printf("%v\n\n", desc)
		os.Stdout.Write(text)
		fmt.Printf("\n")
		fmt.Printf("guilty file: %v\n", guiltyFile)
		if guiltyFile != "" {
			maintainers, err := report.GetMaintainers(*flagKernelSrc, guiltyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to get maintainers: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("maintainers: %v\n", maintainers)
		}
	} else {
		if console := report.ExtractConsoleOutput(text); len(console) != 0 {
			text = console
		}
		text, err = report.Symbolize(filepath.Join(*flagKernelObj, "vmlinux"), text, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to symbolize: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(text)
	}
}
