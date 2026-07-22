// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package clangformat provides a tool to run clang-format on kernel source files.
package clangformat

import (
	"fmt"
	"os"
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

	// Write the style file to a temporary file outside the repository.
	tmpFile, err := os.CreateTemp("", "syz-clang-format-*.clang-format")
	if err != nil {
		return result{}, err
	}
	defer os.Remove(tmpFile.Name())

	style := fmt.Sprintf("BasedOnStyle: InheritParentConfig=%s\nColumnLimit: 100\n", state.KernelScratchSrc)
	if _, err := tmpFile.WriteString(style); err != nil {
		tmpFile.Close()
		return result{}, err
	}
	if err := tmpFile.Close(); err != nil {
		return result{}, err
	}
	if err := osutil.SandboxChown(tmpFile.Name()); err != nil {
		return result{}, err
	}

	cmd := osutil.Command("clang-format", "-style=file:"+tmpFile.Name(), "-i", args.File)
	cmd.Dir = state.KernelScratchSrc
	if err := osutil.Sandbox(cmd, true, true); err != nil {
		return result{}, err
	}

	output, err := osutil.Run(10*time.Minute, cmd)
	if err != nil {
		return result{}, err
	}

	return result{Output: string(output)}, nil
}
