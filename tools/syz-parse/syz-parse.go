// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/syzkaller/pkg/report"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "report":
		if len(os.Args) != 4 {
			usage()
			return
		}
		parseReport(os.Args[2], os.Args[3])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  syz-parse report <OS> <CRASH.log>\n")
	os.Exit(1)
}

func parseReport(os, file string) {
	log, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	reporter, err := report.NewReporter(os, "", "", nil, nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	rep := reporter.Parse(log)
	if rep == nil {
		fmt.Printf("Couldn't find any reports\n")
		return
	}
	fmt.Printf("=======\n")
	fmt.Printf("Title: %v\n", rep.Title)
	fmt.Printf("Corrupted: %v\n", rep.Corrupted)
	fmt.Printf("Report:\n%s\n", rep.Report)
}
