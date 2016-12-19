// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/report"
)

var (
	flagLinux = flag.String("linux", "", "path to linux")
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "usage: syz-symbolize [flags] kernel_log_file\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	text, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open input file: %v\n", err)
		os.Exit(1)
	}
	if _, parsed, _, _ := report.Parse(text, nil); len(parsed) != 0 {
		text = parsed
	}
	text, err = report.Symbolize(filepath.Join(*flagLinux, "vmlinux"), text)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to symbolize: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(text)
}
