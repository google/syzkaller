// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"

	"github.com/google/syzkaller/pkg/aflow"
)

type RunCReproArgs struct {
	Syzkaller       string
	Image           string
	Type            string
	VM              json.RawMessage
	KernelSrc       string
	KernelObj       string
	KernelCommit    string
	KernelConfig    string
	FormattedReproC string
}

type RunCReproResult struct {
	CandidateReproduced  bool
	ConsoleOutput        string
	CandidateBugTitle    string
	CandidateCrashReport string
}

var RunCRepro = aflow.NewFuncAction("run-c-repro", RunCReproFunc)

func RunCReproFunc(ctx *aflow.Context, args RunCReproArgs) (RunCReproResult, error) {
	if args.FormattedReproC == "" {
		return RunCReproResult{}, fmt.Errorf("no C reproducer provided")
	}

	workdir, err := ctx.TempDir()
	if err != nil {
		return RunCReproResult{}, err
	}

	reproduceArgs := ReproduceArgs{
		Syzkaller:    args.Syzkaller,
		Image:        args.Image,
		Type:         args.Type,
		VM:           args.VM,
		KernelSrc:    args.KernelSrc,
		KernelObj:    args.KernelObj,
		KernelCommit: args.KernelCommit,
		KernelConfig: args.KernelConfig,
		ReproC:       args.FormattedReproC,
	}

	res, err := RunTest(reproduceArgs, workdir, false)
	if err != nil {
		// RunTest returns an error if something went wrong during infrastructure setup or similar.
		// We want to return this error so the workflow can handle it.
		return RunCReproResult{}, err
	}

	result := RunCReproResult{
		ConsoleOutput: res.ConsoleOutput,
	}

	if res.Report != nil {
		result.CandidateReproduced = true
		result.CandidateBugTitle = res.Report.Title
		result.CandidateCrashReport = string(res.Report.Report)
	}

	return result, nil
}
