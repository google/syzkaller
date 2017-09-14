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
)

var (
	flagLinux    = flag.String("linux", "", "path to linux kernel source checkout")
	flagLinuxBld = flag.String("linuxbld", "", "path to linux kernel build directory")
	flagArch     = flag.String("arch", "", "arch to generate")
)

type Arch struct {
	CARCH            []string
	KernelHeaderArch string
	CFlags           []string
}

var archs = map[string]*Arch{
	"amd64":   {[]string{"__x86_64__"}, "x86", []string{"-m64"}},
	"386":     {[]string{"__i386__"}, "x86", []string{"-m32"}},
	"arm64":   {[]string{"__aarch64__"}, "arm64", []string{}},
	"arm":     {[]string{"__arm__"}, "arm", []string{"-D__LINUX_ARM_ARCH__=6", "-m32"}},
	"ppc64le": {[]string{"__ppc64__", "__PPC64__", "__powerpc64__"}, "powerpc", []string{"-D__powerpc64__"}},
}

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
	if archs[*flagArch] == nil {
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
				f.undeclared, f.err = processFile(f.name)
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

func processFile(inname string) (map[string]bool, error) {
	outname := strings.TrimSuffix(inname, ".txt") + "_" + *flagArch + ".const"
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
	arch := archs[*flagArch]
	includes := append(info.Includes, "asm/unistd.h")
	consts, undeclared, err := fetchValues(arch.KernelHeaderArch, info.Consts,
		includes, info.Incdirs, arch.CFlags, info.Defines)
	if err != nil {
		return nil, err
	}
	data := compiler.SerializeConsts(consts)
	if err := osutil.WriteFile(outname, data); err != nil {
		return nil, fmt.Errorf("failed to write output file: %v", err)
	}
	return undeclared, nil
}
