// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"fmt"
	"path/filepath"
	"slices"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

// SymbolizePC action resolves a kernel PC address to a source file and line number.
var SymbolizePC = aflow.NewFuncAction("kernel-symbolize-pc", symbolizePC)

type symbolizePCArgs struct {
	PC        uint64
	KernelSrc string
	KernelObj string
}

type InlineFrame struct {
	Func string
	File string
	Line int
}

type symbolizePCResult struct {
	File      string
	Line      int
	InnerFunc string
	OuterFile string
	OuterLine int
	OuterFunc string
	Frames    []InlineFrame
}

func symbolizePC(ctx *aflow.Context, args symbolizePCArgs) (symbolizePCResult, error) {
	if args.PC == 0 {
		return symbolizePCResult{}, fmt.Errorf("invalid PC address: 0")
	}
	target := targets.Get(targets.Linux, targets.AMD64)
	vmlinux := filepath.Join(args.KernelObj, target.KernelObject)
	symb := symbolizer.Make(target)
	defer symb.Close()
	frames, err := symb.Symbolize(vmlinux, args.PC)
	if err != nil {
		return symbolizePCResult{}, fmt.Errorf("failed to symbolize PC 0x%x: %w", args.PC, err)
	}
	if len(frames) == 0 {
		return symbolizePCResult{}, fmt.Errorf("failed to symbolize PC 0x%x: no frames found", args.PC)
	}

	// frames[0] corresponds to the innermost inline or regular function frame.
	frame := frames[0]
	topFrame := frames[len(frames)-1]

	kernelDirs := &mgrconfig.KernelDirs{
		Src: args.KernelSrc,
		Obj: args.KernelObj,
	}

	// Convert absolute path to relative path from the kernel source tree root.
	file, _ := backend.CleanPath(frame.File, kernelDirs, nil)
	outerFile, _ := backend.CleanPath(topFrame.File, kernelDirs, nil)

	var inlineFrames []InlineFrame
	for _, f := range slices.Backward(frames) {
		fFile, _ := backend.CleanPath(f.File, kernelDirs, nil)
		inlineFrames = append(inlineFrames, InlineFrame{
			Func: f.Func,
			File: fFile,
			Line: f.Line,
		})
	}

	return symbolizePCResult{
		File:      file,
		Line:      frame.Line,
		InnerFunc: frame.Func,
		OuterFile: outerFile,
		OuterLine: topFrame.Line,
		OuterFunc: topFrame.Func,
		Frames:    inlineFrames,
	}, nil
}
