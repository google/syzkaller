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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagLinux    = flag.String("linux", "", "path to linux kernel source checkout")
	flagLinuxBld = flag.String("linuxbld", "", "path to linux kernel build directory")
	flagArch     = flag.String("arch", "", "comma-separated list of arches to generate (all by default)")
	flagBuild    = flag.Bool("build", false, "regenerate arch-specific kernel headers")
)

type Arch struct {
	target    *targets.Target
	kernelDir string
	buildDir  string
	build     bool
	files     []*File
	err       error
}

type File struct {
	arch       *Arch
	name       string
	undeclared map[string]bool
	err        error
}

func main() {
	failf := func(msg string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, msg+"\n", args...)
		os.Exit(1)
	}

	const OS = "linux"
	flag.Parse()
	if *flagLinux == "" {
		failf("provide path to linux kernel checkout via -linux flag (or make extract LINUX= flag)")
	}
	if *flagBuild && *flagLinuxBld != "" {
		failf("-build and -linuxbld is an invalid combination")
	}
	n := len(flag.Args())
	if n == 0 {
		failf("usage: syz-extract -linux=/linux/checkout -arch=arch input_file.txt...")
	}

	var archArray []string
	if *flagArch != "" {
		archArray = strings.Split(*flagArch, ",")
	} else {
		for arch := range targets.List[OS] {
			archArray = append(archArray, arch)
		}
		sort.Strings(archArray)
	}

	if *flagBuild {
		// Otherwise out-of-tree build fails.
		fmt.Printf("make mrproper\n")
		out, err := osutil.RunCmd(time.Hour, *flagLinux, "make", "mrproper")
		if err != nil {
			failf("make mrproper failed: %v\n%s\n", err, out)
		}
	} else {
		if len(archArray) > 1 {
			failf("more than 1 arch is invalid without -build")
		}
	}

	jobC := make(chan interface{}, len(archArray)*len(flag.Args()))
	var wg sync.WaitGroup

	var arches []*Arch
	for _, archStr := range archArray {
		buildDir := ""
		if *flagBuild {
			dir, err := ioutil.TempDir("", "syzkaller-kernel-build")
			if err != nil {
				failf("failed to create temp dir: %v", err)
			}
			buildDir = dir
		} else if *flagLinuxBld != "" {
			buildDir = *flagLinuxBld
		} else {
			buildDir = *flagLinux
		}

		target := targets.List[OS][archStr]
		if target == nil {
			failf("unknown arch: %v", archStr)
		}

		arch := &Arch{
			target:    target,
			kernelDir: *flagLinux,
			buildDir:  buildDir,
			build:     *flagBuild,
		}
		for _, f := range flag.Args() {
			arch.files = append(arch.files, &File{
				arch: arch,
				name: f,
			})
		}
		arches = append(arches, arch)
		jobC <- arch
		wg.Add(1)
	}

	for p := 0; p < runtime.GOMAXPROCS(0); p++ {
		go func() {
			for job := range jobC {
				switch j := job.(type) {
				case *Arch:
					if j.build {
						j.err = buildKernel(j)
					}
					if j.err == nil {
						for _, f := range j.files {
							wg.Add(1)
							jobC <- f
						}
					}
				case *File:
					j.undeclared, j.err = processFile(j.arch, j.name)
				}
				wg.Done()
			}
		}()
	}
	wg.Wait()

	for _, arch := range arches {
		if arch.build {
			os.RemoveAll(arch.buildDir)
		}
	}

	for _, arch := range arches {
		fmt.Printf("generating %v/%v...\n", arch.target.OS, arch.target.Arch)
		if arch.err != nil {
			failf("%v", arch.err)
		}
		for _, f := range arch.files {
			fmt.Printf("extracting from %v\n", f.name)
			if f.err != nil {
				failf("%v", f.err)
			}
			for c := range f.undeclared {
				fmt.Printf("undefined const: %v\n", c)
			}
		}
		fmt.Printf("\n")
	}
}

func processFile(arch *Arch, inname string) (map[string]bool, error) {
	outname := strings.TrimSuffix(inname, ".txt") + "_" + arch.target.Arch + ".const"
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
	consts, undeclared, err := fetchValues(arch.target, arch.kernelDir, arch.buildDir, info.Consts, includes, info.Incdirs, info.Defines)
	if err != nil {
		return nil, err
	}
	data := compiler.SerializeConsts(consts)
	if err := osutil.WriteFile(outname, data); err != nil {
		return nil, fmt.Errorf("failed to write output file: %v", err)
	}
	return undeclared, nil
}

func buildKernel(arch *Arch) error {
	target := arch.target
	kernelDir := arch.kernelDir
	buildDir := arch.buildDir
	makeArgs := []string{
		"ARCH=" + target.KernelArch,
		"CROSS_COMPILE=" + target.CCompilerPrefix,
		"CFLAGS=" + strings.Join(target.CrossCFlags, " "),
		"O=" + buildDir,
	}
	out, err := osutil.RunCmd(time.Hour, kernelDir, "make", append(makeArgs, "defconfig")...)
	if err != nil {
		return fmt.Errorf("make defconfig failed: %v\n%s\n", err, out)
	}
	// Without CONFIG_NETFILTER kernel does not build.
	out, err = osutil.RunCmd(time.Minute, buildDir, "sed", "-i",
		"s@# CONFIG_NETFILTER is not set@CONFIG_NETFILTER=y@g", ".config")
	if err != nil {
		return fmt.Errorf("sed .config failed: %v\n%s\n", err, out)
	}
	out, err = osutil.RunCmd(time.Hour, kernelDir, "make", append(makeArgs, "olddefconfig")...)
	if err != nil {
		return fmt.Errorf("make olddefconfig failed: %v\n%s\n", err, out)
	}
	out, err = osutil.RunCmd(time.Hour, kernelDir, "make", append(makeArgs, "init/main.o")...)
	if err != nil {
		return fmt.Errorf("make failed: %v\n%s\n", err, out)
	}
	return nil
}
