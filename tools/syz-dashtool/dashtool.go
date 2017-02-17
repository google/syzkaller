// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-dashtool allow to upload a single crash or all crashes in workdir
// to a dashboard for testing.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/syzkaller/dashboard"
)

var (
	flagAddr   = flag.String("addr", "", "dashboard address")
	flagClient = flag.String("client", "", "dashboard client")
	flagKey    = flag.String("key", "", "dashboard key")
)

func main() {
	flag.Parse()
	if *flagAddr == "" || *flagClient == "" || *flagKey == "" {
		fmt.Fprintf(os.Stderr, "addr/client/key flags are mandatory\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	dash := &dashboard.Dashboard{
		Addr:   *flagAddr,
		Client: *flagClient,
		Key:    *flagKey,
	}
	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "specify command: report, report-all\n")
		os.Exit(1)
	}
	switch flag.Args()[0] {
	case "report":
		if len(flag.Args()) != 2 {
			fmt.Fprintf(os.Stderr, "usage: report logN\n")
			os.Exit(1)
		}
		report(dash, flag.Args()[1])
	case "report-all":
		if len(flag.Args()) != 2 {
			fmt.Fprintf(os.Stderr, "usage: report-all workdir/crashes\n")
			os.Exit(1)
		}
		reportAll(dash, flag.Args()[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %v\n", flag.Args()[0])
		os.Exit(1)
	}
}

func report(dash *dashboard.Dashboard, logfile string) {
	n := -1
	for i := range logfile {
		x, err := strconv.Atoi(logfile[i:])
		if err == nil {
			n = x
			break
		}
	}
	if n == -1 {
		fmt.Fprintf(os.Stderr, "bad log file name\n")
		os.Exit(1)
	}
	dir := filepath.Dir(logfile)

	log, err := ioutil.ReadFile(logfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read log file: %v\n", err)
		os.Exit(1)
	}
	desc, err := ioutil.ReadFile(filepath.Join(dir, "description"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to description file: %v\n", err)
		os.Exit(1)
	}
	tag, _ := ioutil.ReadFile(filepath.Join(dir, fmt.Sprintf("tag%v", n)))
	report, _ := ioutil.ReadFile(filepath.Join(dir, fmt.Sprintf("report%v", n)))

	crash := &dashboard.Crash{
		Tag:    string(tag),
		Desc:   string(desc),
		Log:    log,
		Report: report,
	}

	if err := dash.ReportCrash(crash); err != nil {
		fmt.Fprintf(os.Stderr, "failed: %v\n", err)
		os.Exit(1)
	}
}

func reportAll(dash *dashboard.Dashboard, crashes string) {
	dirs, err := ioutil.ReadDir(crashes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read crashes dir: %v\n", err)
		os.Exit(1)
	}
	for _, dir := range dirs {
		files, err := ioutil.ReadDir(filepath.Join(crashes, dir.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read crashes dir: %v\n", err)
			os.Exit(1)
		}
		for _, file := range files {
			if !strings.HasPrefix(file.Name(), "log") {
				continue
			}
			report(dash, filepath.Join(crashes, dir.Name(), file.Name()))
		}
	}
}
