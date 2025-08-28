// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/osutil"
)

var (
	flagVmlinux         = flag.String("vmlinux", "vmlinux", "Path to vmlinux binary")
	flagTimeout         = flag.Int("timeout", 0, "Timeout in milliseconds")
	flagThreads         = flag.Int("threads", 2, "Number of threads")
	flagDisplayInterval = flag.Int("display", 5, "Display interval")
	flagDisplayProgs    = flag.Bool("display-progs", false, "If enabled, display the last executed prog for each target")
)

func main() {
	usage := func() {
		w := flag.CommandLine.Output()
		fmt.Fprintf(w, "usage: %s [flags] [enabled targets]\n\n", os.Args[0])
		fmt.Fprintln(w, `Args:
  One fuzz test name per enabled fuzz test arg. If empty, defaults to
  all discovered targets.`)
		fmt.Fprintln(w, `Example:
  ./syz-kfuzztest -vmlinux ~/kernel/vmlinux fuzz_target_0 fuzz_target_1`)
		fmt.Fprintln(w, "Flags:")
		flag.PrintDefaults()
	}
	flag.Usage = usage
	flag.Parse()
	enabledTargets := flag.Args()

	cfg := config{
		vmlinuxPath:         *flagVmlinux,
		timeoutMilliseconds: uint32(*flagTimeout),
		displayInterval:     uint32(*flagDisplayInterval),
		numThreads:          *flagThreads,
		enabledTargets:      enabledTargets,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdownChan := make(chan struct{})
	osutil.HandleInterrupts(shutdownChan)
	go func() {
		<-shutdownChan
		cancel()
	}()

	mgr, err := newKFuzzTestManager(ctx, cfg)
	if err != nil {
		panic(err)
	}
	mgr.Run()
}
