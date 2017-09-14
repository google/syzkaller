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
	"time"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys"
)

var (
	flagLinux    = flag.String("linux", "", "path to linux kernel source checkout")
	flagLinuxBld = flag.String("linuxbld", "", "path to linux kernel build directory")
	flagArch     = flag.String("arch", "", "arch to generate")
	flagBuild    = flag.Bool("build", false, "generate arch-specific files in the linux dir")
)

type File struct {
	name       string
	undeclared map[string]bool
	err        error
}

func main() {
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
	if *flagBuild {
		buildKernel(target, *flagLinux)
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

func buildKernel(target *sys.Target, dir string) {
	// TODO(dvyukov): use separate temp build dir.
	// This will allow to do build for all archs in parallel and
	// won't destroy user's build state.
	makeArgs := []string{
		"ARCH=" + target.KernelArch,
		"CROSS_COMPILE=" + target.CCompilerPrefix,
		"CFLAGS=" + strings.Join(target.CrossCFlags, " "),
	}
	out, err := osutil.RunCmd(time.Hour, dir, "make", append(makeArgs, "defconfig")...)
	if err != nil {
		failf("make defconfig failed: %v\n%s\n", err, out)
	}
	// Without CONFIG_NETFILTER kernel does not build.
	out, err = osutil.RunCmd(time.Minute, dir, "sed", "-i",
		"s@# CONFIG_NETFILTER is not set@CONFIG_NETFILTER=y@g", ".config")
	if err != nil {
		failf("sed .config failed: %v\n%s\n", err, out)
	}
	out, err = osutil.RunCmd(time.Hour, dir, "make", append(makeArgs, "olddefconfig")...)
	if err != nil {
		failf("make olddefconfig failed: %v\n%s\n", err, out)
	}
	out, err = osutil.RunCmd(time.Hour, dir, "make", append(makeArgs, "init/main.o")...)
	if err != nil {
		failf("make failed: %v\n%s\n", err, out)
	}
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
