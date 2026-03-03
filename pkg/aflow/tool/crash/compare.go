// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"github.com/google/syzkaller/pkg/aflow"
)

var CompareCrashTool = aflow.NewFuncTool("compare-crash-signature", compareCrashToolFunc, `
Tool to verify if the reproduced crash matches the target crash title.
`)

type CompareCrashToolState struct {
	BugTitle string
}

type CompareCrashToolArgs struct {
	ReproducedBugTitle string `jsonschema:"The title of the crash that was reproduced (returned by crash-reproducer)."`
}

type CompareCrashToolResult struct {
	CrashSignatureMatches bool `jsonschema:"True if the crash matches the target, false otherwise."`
}

func compareCrashToolFunc(ctx *aflow.Context, state CompareCrashToolState, args CompareCrashToolArgs,
) (CompareCrashToolResult, error) {
	action := &aflow.CompareAction{}
	res, err := action.Run(ctx, state.BugTitle, args.ReproducedBugTitle)
	if err != nil {
		return CompareCrashToolResult{}, err
	}
	return CompareCrashToolResult{CrashSignatureMatches: res}, nil
}
