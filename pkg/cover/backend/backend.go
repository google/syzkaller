// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"fmt"

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

type Impl struct {
	Units     []*CompileUnit
	Symbols   []*Symbol
	Frames    []Frame
	Symbolize func(pcs []uint64) ([]Frame, error)
	RestorePC func(pc uint32) uint64
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

type Frame struct {
	symbolizer.Frame
	Path string
}

func Make(target *targets.Target, vm, objDir, srcDir, buildDir string) (*Impl, error) {
	if objDir == "" {
		return nil, fmt.Errorf("kernel obj directory is not specified")
	}
	return makeELF(target, objDir, srcDir, buildDir)
}
