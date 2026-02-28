// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagKernelObj  = flag.String("kernel_obj", "", "path to kernel build/obj dir")
	flagCPUProfile = flag.String("cpuprofile", "", "write cpu profile to file")
	flagInitOnly   = flag.Bool("init_only", false, "benchmark initialization only")
)

func main() {
	flag.Parse()
	if *flagKernelObj == "" {
		fmt.Fprintf(os.Stderr, "usage: bench_symbolize -kernel_obj=path/to/vmlinux < pcs.in\n")
		os.Exit(1)
	}

	if *flagCPUProfile != "" {
		f, err := os.Create(*flagCPUProfile)
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// Read PCs from stdin.
	var pcs []uint64
	if !*flagInitOnly {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			line = strings.TrimSuffix(line, ":")
			if line == "" {
				continue
			}
			pc, err := strconv.ParseUint(line, 0, 64)
			if err == nil {
				pcs = append(pcs, pc)
			}
		}
		fmt.Printf("Loaded %d PCs\n", len(pcs))
	}

	target := targets.Get("linux", "amd64")
	target.KernelObject = *flagKernelObj

	startInit := time.Now()
	symb, err := symbolizer.Make(target, *flagKernelObj)
	if err != nil {
		panic(err)
	}
	defer symb.Close()
	fmt.Printf("Initialization time: %v\n", time.Since(startInit))

	if *flagInitOnly {
		return
	}

	// Benchmark batch symbolization.
	start := time.Now()
	_, err = symb.Symbolize(*flagKernelObj, pcs...)
	if err != nil {
		panic(err)
	}
	duration := time.Since(start)
	fmt.Printf("symbolized %d PCs in %v (Cold)\n", len(pcs), duration)
	fmt.Printf("Speed: %.2f PCs/sec\n", float64(len(pcs))/duration.Seconds())

	// Warm cache pass.
	start = time.Now()
	_, err = symb.Symbolize(*flagKernelObj, pcs...)
	if err != nil {
		panic(err)
	}
	duration = time.Since(start)
	fmt.Printf("symbolized %d PCs in %v (Warm)\n", len(pcs), duration)
	fmt.Printf("Speed: %.2f PCs/sec\n", float64(len(pcs))/duration.Seconds())
}
