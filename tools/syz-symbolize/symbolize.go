// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
)

var (
	flagOS        = flag.String("os", runtime.GOOS, "target os")
	flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
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
	cfg := &mgrconfig.Config{
		TargetOS:   *flagOS,
		TargetArch: *flagArch,
		KernelObj:  *flagKernelObj,
		KernelSrc:  *flagKernelSrc,
	}
	reporter, err := report.NewReporter(cfg)
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
	fmt.Printf("TITLE: %v\n", rep.Title)
	fmt.Printf("CORRUPTED: %v (%v)\n", rep.Corrupted, rep.CorruptedReason)
	fmt.Printf("MAINTAINERS: %v\n", rep.Maintainers)
	fmt.Printf("\n")
	os.Stdout.Write(rep.Report)
}
