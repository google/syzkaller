// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/syzkaller/report"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: syz-report vmlinux report (args %+v)\n", os.Args)
		os.Exit(1)
	}
	output, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read report file: %v\n", err)
		os.Exit(1)
	}
	desc, text, _, _ := report.Parse(output, nil)
	if desc == "" {
		fmt.Fprintf(os.Stderr, "report file does not contain a crash\n")
		os.Exit(1)
	}
	symbolized, err := report.Symbolize(os.Args[1], text)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to symbolize report: %v\n", err)
	} else {
		text = symbolized
	}
	fmt.Printf("%v\n\n%s", desc, text)
}
