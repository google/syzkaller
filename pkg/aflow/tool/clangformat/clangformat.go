// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package clangformat provides a tool to run clang-format on kernel source files.
package clangformat

import (
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
)

var Tool = aflow.NewFuncTool("clang-format", clangFormat, `
The tool runs clang-format on a specific file to fix formatting issues.
WARNING: clang-format may break existing formatting (like manual alignment) and should be used with caution.
`)

type state struct {
	KernelScratchSrc string
}

type args struct {
	File string `jsonschema:"The file to format (relative to the repository root)."`
}

type result struct {
	Output string `jsonschema:"Output of the clang-format command."`
}

func clangFormat(ctx *aflow.Context, state state, args args) (result, error) {
	if state.KernelScratchSrc == "" {
		return result{}, aflow.BadCallError("KernelScratchSrc is not set")
	}
	if args.File == "" {
		return result{}, aflow.BadCallError("File is required")
	}

	cmd := osutil.Command("clang-format", "-style={BasedOnStyle: InheritParentConfig, ColumnLimit: 100}", "-i", args.File)
	cmd.Dir = state.KernelScratchSrc

	output, err := osutil.Run(10*time.Minute, cmd)
	if err != nil {
		return result{}, err
	}

	return result{Output: string(output)}, nil
}
