// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vminfo extracts information about the target VM.
// The package itself runs on the host, which may be a different OS/arch.
// User of the package first requests set of files that needs to be fetched from the VM
// and set of test programs that needs to be executed in the VM (Checker.RequiredThings),
// then fetches these files and executes test programs, and calls Checker.MachineInfo
// to parse the files and extract information about the VM, and optionally calls
// Checker.Check to obtain list of enabled/disabled syscalls.
// The information includes information about kernel modules and OS-specific info
// (for Linux that includes things like parsed /proc/cpuinfo).
package vminfo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type KernelModule struct {
	Name string
	Addr uint64
	Size uint64
	Path string
}

type Checker struct {
	checker
	cfg      *Config
	source   queue.Source
	executor queue.Executor
}

type Config struct {
	Target *prog.Target
	VMType string
	// Set of features to check, missing features won't be checked/enabled after Run.
	Features flatrpc.Feature
	// Set of syscalls to check.
	Syscalls   []int
	Debug      bool
	Cover      bool
	MemoryDump bool
	Sandbox    flatrpc.ExecEnv
	SandboxArg int64
}

func New(cfg *Config) *Checker {
	var impl checker
	switch cfg.Target.OS {
	case targets.Linux:
		impl = &linux{vmType: cfg.VMType}
	case targets.NetBSD:
		impl = new(netbsd)
	case targets.OpenBSD:
		impl = new(openbsd)
	default:
		impl = new(nopChecker)
	}
	executor := queue.Plain()
	return &Checker{
		cfg:      cfg,
		checker:  impl,
		executor: executor,
		source:   queue.Deduplicate(executor),
	}
}

func (checker *Checker) MachineInfo(fileInfos []*flatrpc.FileInfo) ([]*KernelModule, []byte, error) {
	files := createVirtualFilesystem(fileInfos)
	modules, err := checker.parseModules(files)
	if err != nil {
		return nil, nil, err
	}
	info := new(bytes.Buffer)
	tmp := new(bytes.Buffer)
	for _, fn := range checker.machineInfos() {
		tmp.Reset()
		name, err := fn(files, tmp)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, nil, err
			}
			continue
		}
		if tmp.Len() == 0 {
			continue
		}
		fmt.Fprintf(info, "[%v]\n%s\n%v\n\n", name, tmp.Bytes(), strings.Repeat("-", 80))
	}
	return modules, info.Bytes(), nil
}

var ErrAborted = errors.New("aborted through the context")

func (checker *Checker) Run(ctx context.Context, files []*flatrpc.FileInfo, featureInfos []*flatrpc.FeatureInfo) (
	map[*prog.Syscall]bool, map[*prog.Syscall]string, Features, error) {
	cc := newCheckContext(ctx, checker.cfg, checker.checker, checker.executor)
	enabled, disabled, features, err := cc.do(files, featureInfos)
	if ctx.Err() != nil {
		return nil, nil, nil, ErrAborted
	}
	return enabled, disabled, features, err
}

// Implementation of the queue.Source interface.
func (checker *Checker) Next() *queue.Request {
	return checker.source.Next()
}

var _ queue.Source = &Checker{}

type machineInfoFunc func(files filesystem, w io.Writer) (string, error)

type checker interface {
	RequiredFiles() []string
	CheckFiles() []string
	parseModules(files filesystem) ([]*KernelModule, error)
	machineInfos() []machineInfoFunc
	syscallCheck(*checkContext, *prog.Syscall) string
}

type filesystem map[string]*flatrpc.FileInfo

func createVirtualFilesystem(fileInfos []*flatrpc.FileInfo) filesystem {
	files := make(filesystem)
	for _, file := range fileInfos {
		if file.Exists {
			files[file.Name] = file
		}
	}
	return files
}

func (files filesystem) ReadFile(name string) ([]byte, error) {
	file, ok := files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if file.Error != "" {
		return nil, errors.New(file.Error)
	}
	return file.Data, nil
}

func (files filesystem) ReadDir(dir string) []string {
	var res []string
	dedup := make(map[string]bool)
	for _, file := range files {
		if len(file.Name) < len(dir)+2 ||
			!strings.HasPrefix(file.Name, dir) ||
			file.Name[len(dir)] != '/' {
			continue
		}
		name := file.Name[len(dir)+1:]
		if slash := strings.Index(name, "/"); slash != -1 {
			name = name[:slash]
		}
		if dedup[name] {
			continue
		}
		dedup[name] = true
		res = append(res, name)
	}
	return res
}

type nopChecker int

func (nopChecker) RequiredFiles() []string {
	return nil
}

func (nopChecker) CheckFiles() []string {
	return nil
}

func (nopChecker) parseModules(files filesystem) ([]*KernelModule, error) {
	return nil, nil
}

func (nopChecker) machineInfos() []machineInfoFunc {
	return nil
}

func (nopChecker) syscallCheck(*checkContext, *prog.Syscall) string {
	return ""
}
