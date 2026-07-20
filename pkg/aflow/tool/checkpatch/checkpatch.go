// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package checkpatch provides a tool to run the Linux kernel's checkpatch.pl script.
package checkpatch

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
)

var Tool = aflow.NewFuncTool("checkpatch", checkpatch, `
The tool runs the Linux kernel's scripts/checkpatch.pl script on the current patch.
It reports style and formatting issues in the patch.
`)

type state struct {
	KernelScratchSrc string
}

type args struct{}

type result struct {
	Output string `jsonschema:"Output of the checkpatch.pl script."`
}

func checkpatch(ctx *aflow.Context, state state, args args) (result, error) {
	if state.KernelScratchSrc == "" {
		return result{}, aflow.BadCallError("KernelScratchSrc is not set")
	}

	output, _, err := kernel.Checkpatch(state.KernelScratchSrc)
	if err != nil {
		return result{}, err
	}

	return result{Output: output}, nil
}
