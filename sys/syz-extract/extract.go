// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys"
)

var (
	flagLinux    = flag.String("linux", "", "path to linux kernel source checkout")
	flagLinuxBld = flag.String("linuxbld", "", "path to linux kernel build directory")
	flagArch     = flag.String("arch", "", "arch to generate")
)

type File struct {
	name       string
	undeclared map[string]bool
	err        error
}

func main() {
	failf := func(msg string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, msg+"\n", args...)
		os.Exit(1)
	}

	flag.Parse()
	if *flagLinux == "" {
		failf("provide path to linux kernel checkout via -linux flag (or make extract LINUX= flag)")
	}
	if *flagLinuxBld == "" {
		*flagLinuxBld = *flagLinux
	}
	if *flagArch == "" {
		failf("-arch flag is required")
	}
	target := sys.Targets["linux"][*flagArch]
	if target == nil {
		failf("unknown arch %v", *flagArch)
	}
	n := len(flag.Args())
	if n == 0 {
		failf("usage: syz-extract -linux=/linux/checkout -arch=arch input_file.txt...")
	}

	files := make([]File, n)
	inc := make(chan *File, n)
	for i, f := range flag.Args() {
		files[i].name = f
		inc <- &files[i]
	}
	close(inc)

	procs := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	wg.Add(procs)
	for p := 0; p < procs; p++ {
		go func() {
			defer wg.Done()
			for f := range inc {
				f.undeclared, f.err = processFile(target, f.name)
			}
		}()
	}
	wg.Wait()
	for _, f := range files {
		fmt.Printf("extracting from %v\n", f.name)
		if f.err != nil {
			failf("%v", f.err)
		}
		for c := range f.undeclared {
			fmt.Printf("undefined const: %v\n", c)
		}
	}
}

func processFile(target *sys.Target, inname string) (map[string]bool, error) {
	outname := strings.TrimSuffix(inname, ".txt") + "_" + target.Arch + ".const"
	indata, err := ioutil.ReadFile(inname)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file: %v", err)
	}
	errBuf := new(bytes.Buffer)
	eh := func(pos ast.Pos, msg string) {
		fmt.Fprintf(errBuf, "%v: %v\n", pos, msg)
	}
	desc := ast.Parse(indata, filepath.Base(inname), eh)
	if desc == nil {
		return nil, fmt.Errorf("%v", errBuf.String())
	}
	info := compiler.ExtractConsts(desc, eh)
	if info == nil {
		return nil, fmt.Errorf("%v", errBuf.String())
	}
	if len(info.Consts) == 0 {
		return nil, nil
	}
	includes := append(info.Includes, "asm/unistd.h")
	consts, undeclared, err := fetchValues(target, info.Consts, includes, info.Incdirs, info.Defines)
	if err != nil {
		return nil, err
	}
	data := compiler.SerializeConsts(consts)
	if err := osutil.WriteFile(outname, data); err != nil {
		return nil, fmt.Errorf("failed to write output file: %v", err)
	}
	return undeclared, nil
}
