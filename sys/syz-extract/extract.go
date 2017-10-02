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

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagOS        = flag.String("os", "", "target OS")
	flagBuild     = flag.Bool("build", false, "regenerate arch-specific kernel headers")
	flagSourceDir = flag.String("sourcedir", "", "path to kernel source checkout dir")
	flagBuildDir  = flag.String("builddir", "", "path to kernel build dir")
	flagArch      = flag.String("arch", "", "comma-separated list of arches to generate (all by default)")
)

type Arch struct {
	target    *targets.Target
	sourceDir string
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

type OS interface {
	prepare(sourcedir string, build bool, arches []string) error
	prepareArch(arch *Arch) error
	processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error)
}

var oses = map[string]OS{
	"linux":   new(linux),
	"freebsd": new(freebsd),
	"android": new(linux),
	"fuchsia": new(fuchsia),
	"windows": new(windows),
}

func main() {
	failf := func(msg string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, msg+"\n", args...)
		os.Exit(1)
	}
	flag.Parse()

	OS := oses[*flagOS]
	if OS == nil {
		failf("unknown os: %v", *flagOS)
	}
	if *flagBuild && *flagBuildDir != "" {
		failf("-build and -builddir is an invalid combination")
	}
	android := false
	if *flagOS == "android" {
		android = true
		*flagOS = "linux"
	}
	var archArray []string
	if *flagArch != "" {
		archArray = strings.Split(*flagArch, ",")
	} else {
		for arch := range targets.List[*flagOS] {
			archArray = append(archArray, arch)
		}
		if android {
			archArray = []string{"amd64", "arm64"}
		}
		sort.Strings(archArray)
	}
	files := flag.Args()
	if len(files) == 0 {
		matches, err := filepath.Glob(filepath.Join("sys", *flagOS, "*.txt"))
		if err != nil || len(matches) == 0 {
			failf("failed to find sys files: %v", err)
		}
		androidFiles := map[string]bool{
			"ion.txt":        true,
			"tlk_device.txt": true,
		}
		for _, f := range matches {
			f = filepath.Base(f)
			if *flagOS == "linux" && android != androidFiles[f] {
				continue
			}
			files = append(files, filepath.Base(f))
		}
		sort.Strings(files)
	}

	if err := OS.prepare(*flagSourceDir, *flagBuild, archArray); err != nil {
		failf("%v", err)
	}

	jobC := make(chan interface{}, len(archArray)*len(files))
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
		} else if *flagBuildDir != "" {
			buildDir = *flagBuildDir
		} else {
			buildDir = *flagSourceDir
		}

		target := targets.List[*flagOS][archStr]
		if target == nil {
			failf("unknown arch: %v", archStr)
		}

		arch := &Arch{
			target:    target,
			sourceDir: *flagSourceDir,
			buildDir:  buildDir,
			build:     *flagBuild,
		}
		for _, f := range files {
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
					j.err = OS.prepareArch(j)
					if j.err == nil {
						for _, f := range j.files {
							wg.Add(1)
							jobC <- f
						}
					}
				case *File:
					j.undeclared, j.err = processFile(OS, j.arch, j.name)
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

func processFile(OS OS, arch *Arch, inname string) (map[string]bool, error) {
	inname = filepath.Join("sys", arch.target.OS, inname)
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
	info := compiler.ExtractConsts(desc, arch.target, eh)
	if info == nil {
		return nil, fmt.Errorf("%v", errBuf.String())
	}
	if len(info.Consts) == 0 {
		return nil, nil
	}
	consts, undeclared, err := OS.processFile(arch, info)
	if err != nil {
		return nil, err
	}
	data := compiler.SerializeConsts(consts)
	if err := osutil.WriteFile(outname, data); err != nil {
		return nil, fmt.Errorf("failed to write output file: %v", err)
	}
	return undeclared, nil
}
