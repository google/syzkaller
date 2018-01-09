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
	flagKernelSrc = flag.String("kernel_src", ".", "path to kernel sources")
	flagKernelObj = flag.String("kernel_obj", ".", "path to kernel build/obj dir")
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
	rep := reporter.Parse(text)
	if rep == nil {
		rep = &report.Report{Report: text}
	}
	if err := reporter.Symbolize(rep); err != nil {
		fmt.Fprintf(os.Stderr, "failed to symbolize report: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(rep.Report)
}
