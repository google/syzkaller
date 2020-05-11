// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
)

var (
	flagOS        = flag.String("os", runtime.GOOS, "target os")
	flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
	flagKernelObj = flag.String("kernel_obj", ".", "path to kernel build/obj dir")
	flagKernelSrc = flag.String("kernel_src", "", "path to kernel sources (defaults to kernel_obj)")
	flagOutDir    = flag.String("outdir", "", "output directory")
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "usage: syz-symbolize [flags] kernel_log_file\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	cfg := &mgrconfig.Config{
		TargetOS:     *flagOS,
		TargetArch:   *flagArch,
		TargetVMArch: *flagArch,
		KernelObj:    *flagKernelObj,
		KernelSrc:    *flagKernelSrc,
	}
	cfg.CompleteKernelDirs()
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
	// rep := reporter.Parse(text)
	// if rep == nil {
	// 	rep = &report.Report{Report: text}
	// } else if *flagOutDir != "" {
	// 	saveCrash(rep, *flagOutDir)
	// }
	//if err := reporter.Symbolize(rep); err != nil {

	repVec := reporter.ParseMulti(text)	// TOV: Var Arr of reports
	repN := len(repVec)
	if 0 == repN {
		// TOV: If cannot parse, just push everything out
		// repVec = append(repVec, &report.Report{Report: text})
		rep := &report.Report{Report: text}  // TOV: Only one single heap goes to out
		// TOV: There are no _fields_ to print, except for "Report", right?
		//      How it was supposed to print that inexistent stuff then?  TODO: Check
		//
		if err := reporter.Symbolize(rep); err != nil {
			fmt.Fprintf(os.Stderr, "failed to symbolize report: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("TITLE: %v\n", rep.Title)
		fmt.Printf("CORRUPTED: %v (%v)\n", rep.Corrupted, rep.CorruptedReason)
		fmt.Printf("MAINTAINERS: %v\n", rep.Maintainers)
		fmt.Printf("\n")
		os.Stdout.Write(rep.Report)
	} else {
		// TOV: Loop through the vector of reports
		for i := 0;  i < repN;  i++ {
			if *flagOutDir != "" {
				// TOV: TODO: Once per iteration in a loop
				saveCrash(repVec[i], *flagOutDir)
			}
			if err := reporter.Symbolize(repVec[i]); err != nil {
				fmt.Fprintf(os.Stderr, "failed to symbolize report: %v\n", err)
				// TOV: Do we really have to exit in case of single report symbolizing failure?
				//os.Exit(1)
			} else {
				fmt.Printf("TITLE: %v\n", repVec[i].Title)
				fmt.Printf("CORRUPTED: %v (%v)\n", repVec[i].Corrupted, repVec[i].CorruptedReason)
				fmt.Printf("MAINTAINERS: %v\n", repVec[i].Maintainers)
				fmt.Printf("\n")
				os.Stdout.Write(repVec[i].Report)
			}
		}
	}
}

func saveCrash(rep *report.Report, path string) {
	sig := hash.Hash([]byte(rep.Title))
	id := sig.String()
	dir := filepath.Join(path, id)
	osutil.MkdirAll(dir)
	// TOV: "Title" is the only thing that bothers us here?
	//      TODO: Why to exit on every single fail??
	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(rep.Title + "\n")); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write description: %v", err)
		os.Exit(1)
	}

	if err := osutil.WriteFile(filepath.Join(dir, "log"), rep.Output); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write log: %v", err)
		os.Exit(1)
	}

	if len(rep.Report) > 0 {
		if err := osutil.WriteFile(filepath.Join(dir, "report"), rep.Report); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write report: %v", err)
			os.Exit(1)
		}
	}
}
