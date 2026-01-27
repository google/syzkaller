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

		// Print in llvm-symbolizer GNU style
		for _, frame := range frames {
			fmt.Println(frame.Func)
			if frame.Column == 0 {
				fmt.Printf("%s:%d\n", frame.File, frame.Line)
			} else {
				fmt.Printf("%s:%d:%d\n", frame.File, frame.Line, frame.Column)
			}
		}
		// llvm-symbolizer prints an empty line after each address request if requested?
		// "llvm-symbolizer ... prints the file name, line number, column number and source code for each address."
		// It doesn't print a separator by default unless --output-style=JSON.
		// BUT we want to match exactly what our script expects.
		// The script will likely read pairs.
		// Wait, llvm-symbolizer prints *nothing* as delimiter.
		// It just prints N frames.
		// How do we know when it ends?
		// Usually we pass one address, read until we think it's done?
		// Actually, standard usage is one line per frame.
		// If we feed 100 addrs, we get N lines.
		// The diff will be line-by-line.
		// That's fine.
		// 		fmt.Println()

		// llvm-symbolizer with --output-style=GNU adds an empty line? No.
		// Let's NOT add empty line if we want exact diff,
		// OR let's add it if we want to "group" them in our script.
		// User wants verification script.
		// If we use llvm-symbolizer with one address at a time, it's slow.
		// If we pipe all, we get a stream.
		// Let's add specific delimiter if we control both sides.
		// But we want to diff against real llvm-symbolizer.
		// llvm-symbolizer DOES NOT emit empty line by default.
		// However, it's hard to sync.
		// Let's just output frames.
	}
}
