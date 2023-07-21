// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
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
	prepare(sourcedir string, build bool, arches []*Arch) error
	prepareArch(arch *Arch) error
	processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error)
}

var extractors = map[string]Extractor{
	targets.Akaros:  new(akaros),
	targets.Linux:   new(linux),
	targets.FreeBSD: new(freebsd),
	targets.Darwin:  new(darwin),
	targets.NetBSD:  new(netbsd),
	targets.OpenBSD: new(openbsd),
	"android":       new(linux),
	targets.Fuchsia: new(fuchsia),
	targets.Windows: new(windows),
	targets.Trusty:  new(trusty),
}

func main() {
	flag.Parse()
	if *flagBuild && *flagBuildDir != "" {
		tool.Failf("-build and -builddir is an invalid combination")
	}
	OS := *flagOS
	extractor := extractors[OS]
	if extractor == nil {
		tool.Failf("unknown os: %v", OS)
	}
	arches, nfiles, err := createArches(OS, archList(OS, *flagArch), flag.Args())
	if err != nil {
		tool.Fail(err)
	}
	if *flagSourceDir == "" {
		tool.Fail(fmt.Errorf("provide path to kernel checkout via -sourcedir " +
			"flag (or make extract SOURCEDIR)"))
	}
	if err := extractor.prepare(*flagSourceDir, *flagBuild, arches); err != nil {
		tool.Fail(err)
	}

	jobC := make(chan interface{}, len(arches)+nfiles)
	for _, arch := range arches {
		jobC <- arch
	}

	for p := 0; p < runtime.GOMAXPROCS(0); p++ {
		go worker(extractor, jobC)
	}

	failed := false
	constFiles := make(map[string]*compiler.ConstFile)
	for _, arch := range arches {
		fmt.Printf("generating %v/%v...\n", OS, arch.target.Arch)
		<-arch.done
		if arch.err != nil {
			failed = true
			fmt.Printf("%v\n", arch.err)
			continue
		}
		for _, f := range arch.files {
			<-f.done
			if f.err != nil {
				failed = true
				fmt.Printf("%v: %v\n", f.name, f.err)
				continue
			}
			if constFiles[f.name] == nil {
				constFiles[f.name] = compiler.NewConstFile()
			}
			constFiles[f.name].AddArch(f.arch.target.Arch, f.consts, f.undeclared)
		}
	}
	for file, cf := range constFiles {
		outname := filepath.Join("sys", OS, file+".const")
		data := cf.Serialize()
		if len(data) == 0 {
			os.Remove(outname)
			continue
		}
		if err := osutil.WriteFile(outname, data); err != nil {
			tool.Failf("failed to write output file: %v", err)
		}
	}

	if !failed && *flagArch == "" {
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

func worker(extractor Extractor, jobC chan interface{}) {
	for job := range jobC {
		switch j := job.(type) {
		case *Arch:
			infos, err := processArch(extractor, j)
			j.err = err
			close(j.done)
			if j.err == nil {
				for _, f := range j.files {
					f.info = infos[filepath.Join("sys", j.target.OS, f.name)]
					jobC <- f
				}
			}
		case *File:
			j.consts, j.undeclared, j.err = processFile(extractor, j.arch, j)
			close(j.done)
		}
	}
}

func createArches(OS string, archArray, files []string) ([]*Arch, int, error) {
	errBuf := new(bytes.Buffer)
	eh := func(pos ast.Pos, msg string) {
		fmt.Fprintf(errBuf, "%v: %v\n", pos, msg)
	}
	top := ast.ParseGlob(filepath.Join("sys", OS, "*.txt"), eh)
	if top == nil {
		return nil, 0, fmt.Errorf("%v", errBuf.String())
	}
	allFiles := compiler.FileList(top, OS, eh)
	if allFiles == nil {
		return nil, 0, fmt.Errorf("%v", errBuf.String())
	}
	if len(files) == 0 {
		for file := range allFiles {
			files = append(files, file)
		}
	}
	nfiles := 0
	var arches []*Arch
	for _, archStr := range archArray {
		buildDir := ""
		if *flagBuild {
			dir, err := os.MkdirTemp("", "syzkaller-kernel-build")
			if err != nil {
				return nil, 0, fmt.Errorf("failed to create temp dir: %w", err)
			}
			buildDir = dir
		} else if *flagBuildDir != "" {
			buildDir = *flagBuildDir
		} else {
			buildDir = *flagSourceDir
		}

		target := targets.Get(OS, archStr)
		if target == nil {
			return nil, 0, fmt.Errorf("unknown arch: %v", archStr)
		}

		arch := &Arch{
			target:      target,
			sourceDir:   *flagSourceDir,
			includeDirs: *flagIncludes,
			buildDir:    buildDir,
			build:       *flagBuild,
			done:        make(chan bool),
		}
		var archFiles []string
		for _, file := range files {
			meta, ok := allFiles[file]
			if !ok {
				return nil, 0, fmt.Errorf("unknown file: %v", file)
			}
			if meta.NoExtract || !meta.SupportsArch(archStr) {
				continue
			}
			archFiles = append(archFiles, file)
		}
		sort.Strings(archFiles)
		for _, f := range archFiles {
			arch.files = append(arch.files, &File{
				arch: arch,
				name: f,
				done: make(chan bool),
			})
		}
		arches = append(arches, arch)
		nfiles += len(arch.files)
	}
	return arches, nfiles, nil
}

func archList(OS, arches string) []string {
	if arches != "" {
		return strings.Split(arches, ",")
	}
	var archArray []string
	for arch := range targets.List[OS] {
		archArray = append(archArray, arch)
	}
	sort.Strings(archArray)
	return archArray
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
	if file.info == nil {
		return nil, nil, fmt.Errorf("const info for input file %v is missing", inname)
	}
	if len(file.info.Consts) == 0 {
		return nil, nil, nil
	}
	return extractor.processFile(arch, file.info)
}
