// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	actioncrash "github.com/google/syzkaller/pkg/aflow/action/crash"
)

var ReproduceTool = aflow.NewFuncTool("crash-reproducer", reproduceTool, `
Tool to run the syz program in a VM to check if it reproduces the crash.
Returns the reproduced bug title and the crash report if successful.
`)

type ReproduceToolState struct {
	Syzkaller    string
	Image        string
	Type         string
	VM           json.RawMessage
	ReproOpts    string
	ReproC       string
	KernelSrc    string
	KernelObj    string
	KernelCommit string
	KernelConfig string
}

type ReproduceToolArgs struct {
	ReproSyz string `jsonschema:"Candidate syzlang program to test."`
}

type ReproduceToolResult struct {
	ReproducedBugTitle    string `jsonschema:"Title of the bug that was reproduced."`
	ReproducedCrashReport string `jsonschema:"The full crash report."`
}

func reproduceTool(ctx *aflow.Context, state ReproduceToolState, args ReproduceToolArgs) (ReproduceToolResult, error) {
	actionArgs := actioncrash.ReproduceArgs{
		Syzkaller:    state.Syzkaller,
		Image:        state.Image,
		Type:         state.Type,
		VM:           state.VM,
		ReproOpts:    state.ReproOpts,
		ReproC:       state.ReproC,
		KernelSrc:    state.KernelSrc,
		KernelObj:    state.KernelObj,
		KernelCommit: state.KernelCommit,
		KernelConfig: state.KernelConfig,
		ReproSyz:     args.ReproSyz,
	}
	res, err := actioncrash.ReproduceActionFunc(ctx, actionArgs)
	if err != nil {
		// Using the tool it is totally Ok to not trigger any problem.
		if strings.Contains(err.Error(), "reproducer did not crash") {
			return ReproduceToolResult{}, nil
		}
		return ReproduceToolResult{}, err
	}
	return ReproduceToolResult{
		ReproducedBugTitle:    res.ReproducedBugTitle,
		ReproducedCrashReport: res.ReproducedCrashReport,
	}, nil
}
