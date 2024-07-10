// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"fmt"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/sys/targets"
)

type Impl struct {
	Units           []*CompileUnit
	Symbols         []*Symbol
	Frames          []Frame
	Symbolize       func(pcs map[*vminfo.KernelModule][]uint64) ([]Frame, error)
	CallbackPoints  []uint64
	PreciseCoverage bool
}

type CompileUnit struct {
	ObjectUnit
	Path   string
	Module *vminfo.KernelModule
}

type Symbol struct {
	ObjectUnit
	Module     *vminfo.KernelModule
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
	Module   *vminfo.KernelModule
	PC       uint64
	Name     string
	FuncName string
	Path     string
	Inline   bool
	Range
}

type Range struct {
	StartLine int
	StartCol  int
	EndLine   int
	EndCol    int
}

type SecRange struct {
	Start uint64
	End   uint64
}

const LineEnd = 1 << 30

func Make(target *targets.Target, vm, objDir, srcDir, buildDir string, splitBuild bool,
	moduleObj []string, modules []*vminfo.KernelModule) (*Impl, error) {
	if objDir == "" {
		return nil, fmt.Errorf("kernel obj directory is not specified")
	}
	if target.OS == targets.Darwin {
		return makeMachO(target, objDir, srcDir, buildDir, moduleObj, modules)
	}
	if vm == targets.GVisor {
		return makeGvisor(target, objDir, srcDir, buildDir, modules)
	}
	var delimiters []string
	if splitBuild {
		// Path prefixes used by Android Pixel kernels. See
		// https://source.android.com/docs/setup/build/building-pixel-kernels for more
		// details.
		delimiters = []string{"/aosp/", "/private/"}
	}
	return makeELF(target, objDir, srcDir, buildDir, delimiters, moduleObj, modules)
}

func GetPCBase(cfg *mgrconfig.Config) (uint64, error) {
	if cfg.Target.OS == targets.Linux && cfg.Type != targets.GVisor && cfg.Type != targets.Starnix {
		return getLinuxPCBase(cfg)
	}
	return 0, nil
}
