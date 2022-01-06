// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "manager configuration file (manager.cfg)")
	flagCount  = flag.Int("count", 0, "number of VMs to use (overrides config count param)")
	flagDebug  = flag.Bool("debug", false, "print debug output")
	flagOutput = flag.String("output", filepath.Join(".", "repro.txt"), "output description file (output.txt)")
	flagCRepro = flag.String("crepro", filepath.Join(".", "repro.c"), "output c file (repro.c)")
)

func main() {
	os.Args = append(append([]string{}, os.Args[0], "-vv=10"), os.Args[1:]...)
	flag.Parse()
	if len(flag.Args()) != 1 || *flagConfig == "" {
		log.Fatalf("usage: syz-repro -config=manager.cfg execution.log")
	}
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v: %v", *flagConfig, err)
	}
	logFile := flag.Args()[0]
	data, err := ioutil.ReadFile(logFile)
	if err != nil {
		log.Fatalf("failed to open log file %v: %v", logFile, err)
	}
	vmPool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatalf("%v", err)
	}
	vmCount := vmPool.Count()
	if *flagCount > 0 && *flagCount < vmCount {
		vmCount = *flagCount
	}
	if vmCount > 4 {
		vmCount = 4
	}
	vmIndexes := make([]int, vmCount)
	for i := range vmIndexes {
		vmIndexes[i] = i
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}
	osutil.HandleInterrupts(vm.Shutdown)

	res, stats, err := repro.Run(data, cfg, nil, reporter, vmPool, vmIndexes)
	if err != nil {
		log.Logf(0, "reproduction failed: %v", err)
	}
	if stats != nil {
		fmt.Printf("extracting prog: %v\n", stats.ExtractProgTime)
		fmt.Printf("minimizing prog: %v\n", stats.MinimizeProgTime)
		fmt.Printf("simplifying prog options: %v\n", stats.SimplifyProgTime)
		fmt.Printf("extracting C: %v\n", stats.ExtractCTime)
		fmt.Printf("simplifying C: %v\n", stats.SimplifyCTime)
	}
	if res == nil {
		return
	}

	fmt.Printf("opts: %+v crepro: %v\n\n", res.Opts, res.CRepro)

	progSerialized := res.Prog.Serialize()
	fmt.Printf("%s\n", progSerialized)
	if err = osutil.WriteFile(*flagOutput, progSerialized); err == nil {
		fmt.Printf("program saved to %s\n", *flagOutput)
	} else {
		log.Logf(0, "failed to write prog to file: %v", err)
	}

	if res.CRepro {
		src, err := csource.Write(res.Prog, res.Opts)
		if err != nil {
			log.Fatalf("failed to generate C repro: %v", err)
		}
		if formatted, err := csource.Format(src); err == nil {
			src = formatted
		}
		fmt.Printf("%s\n", src)

		if err := osutil.WriteFile(*flagCRepro, src); err == nil {
			fmt.Printf("C file saved to %s\n", *flagCRepro)
		} else {
			log.Logf(0, "failed to write C repro to file: %v", err)
		}
	}
}
