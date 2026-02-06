// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagKernelObj = flag.String("kernel_obj", "", "path to kernel build/obj dir")
	flagWorkers   = flag.Int("workers", 1, "number of concurrent workers")
)

func main() {
	flag.Parse()
	if *flagKernelObj == "" {
		fmt.Fprintf(os.Stderr, "usage: syz-sym-check -kernel_obj=path/to/vmlinux\n")
		os.Exit(1)
	}

	target := targets.Get("linux", "amd64")
	target.KernelObject = *flagKernelObj

	// Force native symbolizer (though symbolizer.Make should do it for AMD64)
	symb, err := symbolizer.Make(target, *flagKernelObj)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create symbolizer: %v\n", err)
		os.Exit(1)
	}
	defer symb.Close()

	// Read all PCs first to avoid race on scanner
	var pcs []uint64
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		pc, err := strconv.ParseUint(line, 0, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse PC %q: %v\n", line, err)
			continue
		}
		pcs = append(pcs, pc)
	}

	pcChan := make(chan uint64, len(pcs))
	for _, pc := range pcs {
		pcChan <- pc
	}
	close(pcChan)

	var wg sync.WaitGroup
	wg.Add(*flagWorkers)

	for i := 0; i < *flagWorkers; i++ {
		go func() {
			defer wg.Done()
			for pc := range pcChan {
				frames, err := symb.Symbolize(*flagKernelObj, pc)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to symbolize %x: %v\n", pc, err)
					continue
				}

				if *flagWorkers == 1 {
					// Print in llvm-symbolizer GNU style only for single worker
					for _, frame := range frames {
						fmt.Println(frame.Func)
						file := frame.File
						if file == "" {
							file = "??"
						}
						fmt.Printf("%s:%d:%d\n", file, frame.Line, frame.Column)
					}
				}
			}
		}()
	}
	wg.Wait()
}
