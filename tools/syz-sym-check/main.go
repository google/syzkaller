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

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagKernelObj = flag.String("kernel_obj", "", "path to kernel build/obj dir")
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
	symb, err := symbolizer.Make(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create symbolizer: %v\n", err)
		os.Exit(1)
	}
	defer symb.Close()

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

		frames, err := symb.Symbolize(*flagKernelObj, pc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to symbolize %x: %v\n", pc, err)
			// Print something to keep sync?
			continue
		}

		// Print in llvm-symbolizer GNU style.
		for _, frame := range frames {
			fmt.Println(frame.Func)
			if frame.Column == 0 {
				fmt.Printf("%s:%d\n", frame.File, frame.Line)
			} else {
				fmt.Printf("%s:%d:%d\n", frame.File, frame.Line, frame.Column)
			}
		}
	}
}
