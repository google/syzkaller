// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"fmt"

	"github.com/google/syzkaller/sys/targets"
)

type KernelModule struct {
	Name string
	Path string
	Addr uint64
}

type Impl struct {
	Units     []*CompileUnit
	Symbols   []*Symbol
	Frames    []Frame
	Symbolize func(pcs []uint64, obj string) ([]Frame, error)
	RestorePC func(pc uint32) uint64
	Modules   map[string]KernelModule
}

type CompileUnit struct {
	ObjectUnit
	Path string
}

type Symbol struct {
	ObjectUnit
	Unit       *CompileUnit
	Start      uint64
	End        uint64
	Symbolized bool
}

// ObjectUnit represents either CompileUnit or Symbol.
type ObjectUnit struct {
	Name string
	PCs  []uint64 // PCs we can get in coverage callbacks for this unit.
	CMPs []uint64 // PCs we can get in comparison interception callbacks for this unit.
}

type Frame struct {
	Module string
	PC     uint64
	Name   string
	Path   string
	Range
}

type Range struct {
	StartLine int
	StartCol  int
	EndLine   int
	EndCol    int
}

const LineEnd = 1 << 30

func Make(target *targets.Target, vm, objDir, srcDir, buildDir string,
	moduleObj []string, modules map[string]KernelModule) (*Impl, error) {
	if objDir == "" {
		return nil, fmt.Errorf("kernel obj directory is not specified")
	}
	if vm == "gvisor" {
		return makeGvisor(target, objDir, srcDir, buildDir, modules)
	}
	return makeELF(target, objDir, srcDir, buildDir, moduleObj, modules)
}

var GroupPCsByModule = func(pcs []uint64, modules map[string]KernelModule) map[string][]uint64 {
	groupPCs := make(map[string][]uint64)
	groupPCs[""] = pcs
	return groupPCs
}
