// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

type Impl struct {
	Units     []*CompileUnit
	Symbols   []*Symbol
	Frames    []symbolizer.Frame
	Symbolize func(pcs []uint64) ([]symbolizer.Frame, error)
}

type CompileUnit struct {
	Name string
	Path string
	PCs  []uint64
}

type Symbol struct {
	Unit       *CompileUnit
	Name       string
	Start      uint64
	End        uint64
	PCs        []uint64
	Symbolized bool
}

func Make(target *targets.Target, vm, kernelObject, srcDir, buildDir string) (*Impl, error) {
	return makeELF(target, kernelObject, srcDir, buildDir)
}
