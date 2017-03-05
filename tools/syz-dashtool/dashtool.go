// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-dashtool allow to upload a single crash or all crashes in workdir
// to a dashboard for testing.
package main

import (
	"bytes"
	"encoding/hex"
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
		fmt.Fprintf(os.Stderr, "specify command: report-crash/report-repro/report-all\n")
		os.Exit(1)
	}
	switch flag.Args()[0] {
	case "report-crash":
		if len(flag.Args()) != 2 {
			fmt.Fprintf(os.Stderr, "usage: report-crash logN\n")
			os.Exit(1)
		}
		reportCrash(dash, flag.Args()[1])
	case "report-repro":
		if len(flag.Args()) != 2 {
			fmt.Fprintf(os.Stderr, "usage: report-repro crashdir\n")
			os.Exit(1)
		}
		reportRepro(dash, flag.Args()[1])
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

func reportCrash(dash *dashboard.Dashboard, logfile string) {
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
		fmt.Fprintf(os.Stderr, "failed to read description file: %v\n", err)
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

func reportRepro(dash *dashboard.Dashboard, crashdir string) {
	desc, err := ioutil.ReadFile(filepath.Join(crashdir, "description"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read description file: %v\n", err)
		os.Exit(1)
	}
	prog, err := ioutil.ReadFile(filepath.Join(crashdir, "repro.prog"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to repro.prog file: %v\n", err)
		os.Exit(1)
	}
	report, err := ioutil.ReadFile(filepath.Join(crashdir, "repro.report"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to repro.report file: %v\n", err)
		os.Exit(1)
	}
	tag, _ := ioutil.ReadFile(filepath.Join(crashdir, "repro.tag"))
	cprog, _ := ioutil.ReadFile(filepath.Join(crashdir, "repro.cprog"))
	opts := ""
	if nl := bytes.IndexByte(prog, '\n'); nl > 1 && prog[0] == '#' {
		opts = string(prog[:nl-1])
		prog = prog[nl+1:]
	}

	repro := &dashboard.Repro{
		Crash: dashboard.Crash{
			Tag:    string(tag),
			Desc:   string(desc),
			Report: report,
		},
		Reproduced: true,
		Opts:       opts,
		Prog:       prog,
		CProg:      cprog,
	}
	if err := dash.ReportRepro(repro); err != nil {
		fmt.Fprintf(os.Stderr, "failed: %v\n", err)
		os.Exit(1)
	}
}

func reportAll(dash *dashboard.Dashboard, crashes string) {
	if _, err := os.Stat(filepath.Join(crashes, "description")); err == nil {
		uploadDir(dash, crashes)
		return
	}
	dirs, err := ioutil.ReadDir(crashes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read crashes dir: %v\n", err)
		os.Exit(1)
	}
	for _, dir := range dirs {
		if !dir.IsDir() || !isCrashDir(dir.Name()) {
			continue
		}
		uploadDir(dash, filepath.Join(crashes, dir.Name()))
	}
}

func uploadDir(dash *dashboard.Dashboard, dir string) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read crashes dir: %v\n", err)
		os.Exit(1)
	}
	for _, file := range files {
		switch {
		case strings.HasPrefix(file.Name(), "log"):
			reportCrash(dash, filepath.Join(dir, file.Name()))
		case file.Name() == "repro.prog":
			reportRepro(dash, dir)
		}
	}
}

func isCrashDir(dir string) bool {
	if len(dir) != 40 {
		return false
	}
	if _, err := hex.DecodeString(dir); err != nil {
		return false
	}
	return true
}
