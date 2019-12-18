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
	flagOS        = flag.String("os", runtime.GOOS, "target OS")
	flagBuild     = flag.Bool("build", false, "regenerate arch-specific kernel headers")
	flagSourceDir = flag.String("sourcedir", "", "path to kernel source checkout dir")
	flagIncludes  = flag.String("includedirs", "", "path to other kernel source include dirs separated by commas")
	flagBuildDir  = flag.String("builddir", "", "path to kernel build dir")
	flagArch      = flag.String("arch", "", "comma-separated list of arches to generate (all by default)")
)

type Arch struct {
	target      *targets.Target
	sourceDir   string
	includeDirs string
	buildDir    string
	build       bool
	files       []*File
	err         error
	done        chan bool
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

type Extractor interface {
	prepare(sourcedir string, build bool, arches []string) error
	prepareArch(arch *Arch) error
	processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error)
}

var extractors = map[string]Extractor{
	"akaros":  new(akaros),
	"linux":   new(linux),
	"freebsd": new(freebsd),
	"netbsd":  new(netbsd),
	"openbsd": new(openbsd),
	"android": new(linux),
	"fuchsia": new(fuchsia),
	"windows": new(windows),
	"trusty":  new(trusty),
}

func main() {
	failf := func(msg string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, msg+"\n", args...)
		os.Exit(1)
	}
	flag.Parse()
	if *flagBuild && *flagBuildDir != "" {
		failf("-build and -builddir is an invalid combination")
	}

	OS, archArray, files, err := archFileList(*flagOS, *flagArch, flag.Args())
	if err != nil {
		failf("%v", err)
	}

	extractor := extractors[OS]
	if extractor == nil {
		failf("unknown os: %v", OS)
	}
	if err := extractor.prepare(*flagSourceDir, *flagBuild, archArray); err != nil {
		failf("%v", err)
	}

	arches, err := createArches(OS, archArray, files)
	if err != nil {
		failf("%v", err)
	}
	jobC := make(chan interface{}, len(archArray)*len(files))
	for _, arch := range arches {
		jobC <- arch
	}

	for p := 0; p < runtime.GOMAXPROCS(0); p++ {
		go func() {
			for job := range jobC {
				switch j := job.(type) {
				case *Arch:
					infos, err := processArch(extractor, j)
					j.err = err
					close(j.done)
					if j.err == nil {
						for _, f := range j.files {
							f.info = infos[f.name]
							jobC <- f
						}
					}
				case *File:
					j.consts, j.undeclared, j.err = processFile(extractor, j.arch, j)
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
			<-f.done
			if f.err != nil {
				failed = true
				fmt.Printf("%v: %v\n", f.name, f.err)
				continue
			}
		}
	}

	if !failed {
		failed = checkUnsupportedCalls(arches)
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

func createArches(OS string, archArray, files []string) ([]*Arch, error) {
	var arches []*Arch
	for _, archStr := range archArray {
		buildDir := ""
		if *flagBuild {
			dir, err := ioutil.TempDir("", "syzkaller-kernel-build")
			if err != nil {
				return nil, fmt.Errorf("failed to create temp dir: %v", err)
			}
			buildDir = dir
		} else if *flagBuildDir != "" {
			buildDir = *flagBuildDir
		} else {
			buildDir = *flagSourceDir
		}

		target := targets.Get(OS, archStr)
		if target == nil {
			return nil, fmt.Errorf("unknown arch: %v", archStr)
		}

		arch := &Arch{
			target:      target,
			sourceDir:   *flagSourceDir,
			includeDirs: *flagIncludes,
			buildDir:    buildDir,
			build:       *flagBuild,
			done:        make(chan bool),
		}
		for _, f := range files {
			arch.files = append(arch.files, &File{
				arch: arch,
				name: f,
				done: make(chan bool),
			})
		}
		arches = append(arches, arch)
	}
	return arches, nil
}

func checkUnsupportedCalls(arches []*Arch) bool {
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
	failed := false
	for name, file := range unsupported {
		if supported[name] {
			continue
		}
		failed = true
		fmt.Printf("%v: %v is unsupported on all arches (typo?)\n",
			file, name)
	}
	return failed
}

func archFileList(os, arch string, files []string) (string, []string, []string, error) {
	android := false
	if os == "android" {
		android = true
		os = "linux"
	}
	var arches []string
	if arch != "" {
		arches = strings.Split(arch, ",")
	} else {
		for arch := range targets.List[os] {
			arches = append(arches, arch)
		}
		if android {
			arches = []string{"386", "amd64", "arm", "arm64"}
		}
		sort.Strings(arches)
	}
	if len(files) == 0 {
		matches, err := filepath.Glob(filepath.Join("sys", os, "*.txt"))
		if err != nil || len(matches) == 0 {
			return "", nil, nil, fmt.Errorf("failed to find sys files: %v", err)
		}
		manualFiles := map[string]bool{
			// Not upstream, generated on https://github.com/multipath-tcp/mptcp_net-next
			"mptcp.txt": true,
		}
		androidFiles := map[string]bool{
			"dev_tlk_device.txt": true,
			// This was generated on:
			// https://source.codeaurora.org/quic/la/kernel/msm-4.9 msm-4.9
			"dev_video4linux.txt": true,
		}
		for _, f := range matches {
			f = filepath.Base(f)
			if manualFiles[f] || os == "linux" && android != androidFiles[f] {
				continue
			}
			files = append(files, f)
		}
		sort.Strings(files)
	}
	return os, arches, files, nil
}

func processArch(extractor Extractor, arch *Arch) (map[string]*compiler.ConstInfo, error) {
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
	if err := extractor.prepareArch(arch); err != nil {
		return nil, err
	}
	return infos, nil
}

func processFile(extractor Extractor, arch *Arch, file *File) (map[string]uint64, map[string]bool, error) {
	inname := filepath.Join("sys", arch.target.OS, file.name)
	outname := strings.TrimSuffix(inname, ".txt") + "_" + arch.target.Arch + ".const"
	if file.info == nil {
		return nil, nil, fmt.Errorf("input file %v is missing", inname)
	}
	if len(file.info.Consts) == 0 {
		os.Remove(outname)
		return nil, nil, nil
	}
	consts, undeclared, err := extractor.processFile(arch, file.info)
	if err != nil {
		return nil, nil, err
	}
	data := compiler.SerializeConsts(consts, undeclared)
	if err := osutil.WriteFile(outname, data); err != nil {
		return nil, nil, fmt.Errorf("failed to write output file: %v", err)
	}
	return consts, undeclared, nil
}
