// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/syzkaller/config"
	"github.com/google/syzkaller/csource"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/repro"
	"github.com/google/syzkaller/vm"
	_ "github.com/google/syzkaller/vm/adb"
	_ "github.com/google/syzkaller/vm/gce"
	_ "github.com/google/syzkaller/vm/kvm"
	_ "github.com/google/syzkaller/vm/odroid"
	_ "github.com/google/syzkaller/vm/qemu"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagCount  = flag.Int("count", 0, "number of VMs to use (overrides config count param)")
)

func main() {
	os.Args = append(append([]string{}, os.Args[0], "-v=10"), os.Args[1:]...)
	flag.Parse()
	cfg, _, err := config.Parse(*flagConfig)
	if err != nil {
		Fatalf("%v", err)
	}
	if *flagCount > 0 {
		cfg.Count = *flagCount
	}
	if cfg.Count > 4 {
		cfg.Count = 4
	}
	if len(flag.Args()) != 1 {
		Fatalf("usage: syz-repro -config=config.file execution.log")
	}
	data, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		Fatalf("failed to open log file: %v", err)
	}
	vmIndexes := make([]int, cfg.Count)
	for i := range vmIndexes {
		vmIndexes[i] = i
	}

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		<-c
		close(vm.Shutdown)
		Logf(-1, "shutting down...")
		<-c
		Fatalf("terminating")
	}()

	res, err := repro.Run(data, cfg, vmIndexes)
	if err != nil {
		Logf(0, "reproduction failed: %v", err)
	}
	if res == nil {
		return
	}

	fmt.Printf("opts: %+v crepro: %v\n\n", res.Opts, res.CRepro)
	fmt.Printf("%s\n", res.Prog.Serialize())
	if res.CRepro {
		src, err := csource.Write(res.Prog, res.Opts)
		if err != nil {
			Fatalf("failed to generate C repro: %v", err)
		}
		if formatted, err := csource.Format(src); err == nil {
			src = formatted
		}
		fmt.Printf("%s\n", src)
	}
}
