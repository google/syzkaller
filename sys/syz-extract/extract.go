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
	done      chan bool
}

type File struct {
	arch       *Arch
	name       string
	consts     map[string]uint64
	undeclared map[string]bool
	info       *compiler.ConstInfo
	err        error
	done       chan bool
}

type OS interface {
	prepare(sourcedir string, build bool, arches []string) error
	prepareArch(arch *Arch) error
	processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error)
}

var oses = map[string]OS{
	"akaros":  new(akaros),
	"linux":   new(linux),
	"freebsd": new(freebsd),
	"netbsd":  new(netbsd),
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
			done:      make(chan bool),
		}
		for _, f := range files {
			arch.files = append(arch.files, &File{
				arch: arch,
				name: f,
				done: make(chan bool),
			})
		}
		arches = append(arches, arch)
		jobC <- arch
	}

	for p := 0; p < runtime.GOMAXPROCS(0); p++ {
		go func() {
			for job := range jobC {
				switch j := job.(type) {
				case *Arch:
					infos, err := processArch(OS, j)
					j.err = err
					close(j.done)
					if j.err == nil {
						for _, f := range j.files {
							f.info = infos[f.name]
							jobC <- f
						}
					}
				case *File:
					j.consts, j.undeclared, j.err = processFile(OS, j.arch, j)
					close(j.done)
				}
			}
		}()
	}

	failed := false
	for _, arch := range arches {
		fmt.Printf("generating %v/%v...\n", arch.target.OS, arch.target.Arch)
		<-arch.done
		if arch.err != nil {
			failed = true
			fmt.Printf("	%v\n", arch.err)
			continue
		}
		for _, f := range arch.files {
			fmt.Printf("extracting from %v\n", f.name)
			<-f.done
			if f.err != nil {
				failed = true
				fmt.Printf("	%v\n", f.err)
				continue
			}
		}
		fmt.Printf("\n")
	}

	if !failed {
		supported := make(map[string]bool)
		unsupported := make(map[string]string)
		for _, arch := range arches {
			for _, f := range arch.files {
				for name := range f.consts {
					supported[name] = true
				}
				for name := range f.undeclared {
					unsupported[name] = f.name
				}
			}
		}
		for name, file := range unsupported {
			if supported[name] {
				continue
			}
			failed = true
			fmt.Printf("%v: %v is unsupported on all arches (typo?)\n",
				file, name)
		}
	}

	for _, arch := range arches {
		if arch.build {
			os.RemoveAll(arch.buildDir)
		}
	}
	if failed {
		os.Exit(1)
	}
}

func processArch(OS OS, arch *Arch) (map[string]*compiler.ConstInfo, error) {
	errBuf := new(bytes.Buffer)
	eh := func(pos ast.Pos, msg string) {
		fmt.Fprintf(errBuf, "%v: %v\n", pos, msg)
	}
	top := ast.ParseGlob(filepath.Join("sys", arch.target.OS, "*.txt"), eh)
	if top == nil {
		return nil, fmt.Errorf("%v", errBuf.String())
	}
	infos := compiler.ExtractConsts(top, arch.target, eh)
	if infos == nil {
		return nil, fmt.Errorf("%v", errBuf.String())
	}
	if err := OS.prepareArch(arch); err != nil {
		return nil, err
	}
	return infos, nil
}

func processFile(OS OS, arch *Arch, file *File) (map[string]uint64, map[string]bool, error) {
	inname := filepath.Join("sys", arch.target.OS, file.name)
	outname := strings.TrimSuffix(inname, ".txt") + "_" + arch.target.Arch + ".const"
	if file.info == nil {
		return nil, nil, fmt.Errorf("input file %v is missing", inname)
	}
	if len(file.info.Consts) == 0 {
		os.Remove(outname)
		return nil, nil, nil
	}
	consts, undeclared, err := OS.processFile(arch, file.info)
	if err != nil {
		return nil, nil, err
	}
	data := compiler.SerializeConsts(consts, undeclared)
	if err := osutil.WriteFile(outname, data); err != nil {
		return nil, nil, fmt.Errorf("failed to write output file: %v", err)
	}
	return consts, undeclared, nil
}
