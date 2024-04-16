// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vminfo extracts information about the target VM.
// The package itself runs on the host, which may be a different OS/arch.
// User of the package first requests set of files that needs to be fetched from the VM
// (Checker.RequiredFiles), then fetches these files, and calls Checker.MachineInfo
// to parse the files and extract information about the VM.
// The information includes information about kernel modules and OS-specific info
// (for Linux that includes things like parsed /proc/cpuinfo).
package vminfo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

type Checker struct {
	checker
}

func New(cfg *mgrconfig.Config) *Checker {
	switch {
	case cfg.TargetOS == targets.Linux:
		return &Checker{new(linux)}
	default:
		return &Checker{new(stub)}
	}
}

func (checker *Checker) MachineInfo(fileInfos []host.FileInfo) ([]host.KernelModule, []byte, error) {
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

type machineInfoFunc func(files filesystem, w io.Writer) (string, error)

type checker interface {
	RequiredFiles() []string
	parseModules(files filesystem) ([]host.KernelModule, error)
	machineInfos() []machineInfoFunc
}

type filesystem map[string]host.FileInfo

func createVirtualFilesystem(fileInfos []host.FileInfo) filesystem {
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

type stub int

func (stub) RequiredFiles() []string {
	return nil
}

func (stub) parseModules(files filesystem) ([]host.KernelModule, error) {
	return nil, nil
}

func (stub) machineInfos() []machineInfoFunc {
	return nil
}
