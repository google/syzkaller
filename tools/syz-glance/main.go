// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/glance"
	_ "github.com/google/syzkaller/tools/clang/glance"
)

func main() {
	force := flag.Bool("force", false, "force regeneration of summary (bypass cache)")
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: syz-glance <kernel-src> <file-path>\n")
		os.Exit(1)
	}

	kernelSrc, err := filepath.Abs(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get absolute path of kernel-src: %v\n", err)
		os.Exit(1)
	}

	filePath := args[1]
	// Assume kernelObj is the same as kernelSrc for simplicity in CLI
	kernelObj := kernelSrc

	orc := glance.NewOrchestrator(kernelSrc, kernelObj, filepath.Join(kernelSrc, "glance"))

	var summary string

	info, err := os.Stat(filepath.Join(kernelSrc, filePath))
	if err == nil && info.IsDir() {
		summary, err = orc.SummarizeDirectory(context.Background(), filePath, *force)
	} else {
		summary, err = orc.Summarize(context.Background(), filePath, *force)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(summary)
}
