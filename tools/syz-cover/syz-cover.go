// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-cover generates coverage HTML report from raw coverage files.
// Raw coverage files are text files with one PC in hex form per line, e.g.:
//
//	0xffffffff8398658d
//	0xffffffff839862fc
//	0xffffffff8398633f
//
// Raw coverage files can be obtained either from /rawcover manager HTTP handler,
// or from syz-execprog with -coverfile flag.
//
// Usage:
//	syz-cover [-os=OS -arch=ARCH -kernel_src=. -kernel_obj=.] rawcover.file*
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	var (
		flagOS             = flag.String("os", runtime.GOOS, "target os")
		flagArch           = flag.String("arch", runtime.GOARCH, "target arch")
		flagKernelSrc      = flag.String("kernel_src", "", "path to kernel sources")
		flagKernelBuildSrc = flag.String("kernel_build_src", "", "path to kernel image's build dir (optional)")
		flagKernelObj      = flag.String("kernel_obj", "", "path to kernel build/obj dir")
	)
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "usage: syz-cover [flags] rawcover.file\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *flagKernelSrc == "" {
		*flagKernelSrc = "."
	}
	if *flagKernelObj == "" {
		*flagKernelObj = *flagKernelSrc
	}
	if *flagKernelBuildSrc == "" {
		*flagKernelBuildSrc = *flagKernelSrc
	}
	target := targets.Get(*flagOS, *flagArch)
	if target == nil {
		failf("unknown target %v/%v", *flagOS, *flagArch)
	}
	pcs, err := readPCs(flag.Args())
	if err != nil {
		failf("%v", err)
	}
	kernelObj := filepath.Join(*flagKernelObj, target.KernelObject)
	rg, err := cover.MakeReportGenerator(target, kernelObj, *flagKernelSrc, *flagKernelBuildSrc)
	if err != nil {
		failf("%v", err)
	}
	progs := []cover.Prog{{PCs: pcs}}
	buf := new(bytes.Buffer)
	if err := rg.Do(buf, progs); err != nil {
		failf("%v", err)
	}
	fn, err := osutil.TempFile("syz-cover")
	if err != nil {
		failf("%v", err)
	}
	fn += ".html"
	if err := osutil.WriteFile(fn, buf.Bytes()); err != nil {
		failf("%v", err)
	}
	if err := exec.Command("xdg-open", fn).Start(); err != nil {
		failf("failed to start browser: %v", err)
	}
}

func readPCs(files []string) ([]uint64, error) {
	var pcs []uint64
	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for s := bufio.NewScanner(bytes.NewReader(data)); s.Scan(); {
			line := strings.TrimSpace(s.Text())
			if line == "" {
				continue
			}
			pc, err := strconv.ParseUint(line, 0, 64)
			if err != nil {
				return nil, err
			}
			pcs = append(pcs, pc)
		}
	}
	return pcs, nil
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
