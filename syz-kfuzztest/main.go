// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	manager "github.com/google/syzkaller/pkg/kfuzztest-manager"
	"github.com/google/syzkaller/pkg/osutil"
)

var (
	flagVmlinux         = flag.String("vmlinux", "vmlinux", "path to vmlinux binary")
	flagCooldown        = flag.Int("cooldown", 0, "cooldown between KFuzzTest target invocations in seconds")
	flagThreads         = flag.Int("threads", 2, "number of threads")
	flagDisplayInterval = flag.Int("display", 5, "number of seconds between console outputs")
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

	cfg := manager.Config{
		VmlinuxPath:     *flagVmlinux,
		Cooldown:        uint32(*flagCooldown),
		DisplayInterval: uint32(*flagDisplayInterval),
		NumThreads:      *flagThreads,
		EnabledTargets:  enabledTargets,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdownChan := make(chan struct{})
	osutil.HandleInterrupts(shutdownChan)
	go func() {
		<-shutdownChan
		cancel()
	}()

	mgr, err := manager.NewKFuzzTestManager(ctx, cfg)
	if err != nil {
		panic(err)
	}
	mgr.Run(ctx)
}
