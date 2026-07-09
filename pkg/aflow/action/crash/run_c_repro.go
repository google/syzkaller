// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"

	"github.com/google/syzkaller/pkg/aflow"
)

type RunCReproArgs struct {
	TargetArch      string
	Syzkaller       string
	Image           string
	Type            string
	VM              json.RawMessage
	KernelSrc       string
	KernelObj       string
	KernelCommit    string
	KernelConfig    string
	FormattedReproC string
	StraceBin       string
	NeedStrace      bool
}

type RunCReproResult struct {
	CandidateReproduced  bool
	ConsoleOutput        string
	StraceOutput         string
	CandidateBugTitle    string
	CandidateCrashReport string
	OtherCrashReports    []string
	TestError            string
}

var RunCRepro = aflow.NewFuncAction("run-c-repro", RunCReproFunc)

func RunCReproFunc(ctx *aflow.Context, args RunCReproArgs) (RunCReproResult, error) {
	if args.FormattedReproC == "" {
		return RunCReproResult{}, fmt.Errorf("no C reproducer provided")
	}
	if args.TargetArch == "" {
		return RunCReproResult{}, fmt.Errorf("TargetArch must not be empty")
	}

	workdir, err := ctx.TempDir()
	if err != nil {
		return RunCReproResult{}, err
	}

	reproduceArgs := ReproduceArgs{
		TargetConfig: TargetConfig{
			TargetArch:   args.TargetArch,
			Syzkaller:    args.Syzkaller,
			Image:        args.Image,
			Type:         args.Type,
			VM:           args.VM,
			KernelSrc:    args.KernelSrc,
			KernelObj:    args.KernelObj,
			KernelCommit: args.KernelCommit,
			KernelConfig: args.KernelConfig,
			StraceBin:    args.StraceBin,
		},
		ReproC: args.FormattedReproC,
	}

	// Run 1: without strace.
	res1, err1 := RunTest(reproduceArgs, workdir, false)
	if err1 != nil {
		return RunCReproResult{}, err1
	}

	result := RunCReproResult{
		ConsoleOutput: res1.ConsoleOutput,
		TestError:     res1.BootError,
	}
	if res1.Report != nil {
		result.CandidateReproduced = true
		result.CandidateBugTitle = res1.Report.Title
		result.CandidateCrashReport = string(res1.Report.Report)
	}
	for _, rep := range res1.OtherReports {
		result.OtherCrashReports = append(result.OtherCrashReports, string(rep.Report))
	}

	// Run 2: with strace (only if first run didn't crash and didn't have boot error)
	if !result.CandidateReproduced && result.TestError == "" && args.NeedStrace && args.StraceBin != "" {
		reproduceArgs.NeedStrace = true
		res2, err2 := RunTest(reproduceArgs, workdir, false)
		if err2 != nil {
			return result, err2 // Return what we had from Run 1, plus the error.
		}

		result.StraceOutput = res2.ConsoleOutput
		if res2.BootError != "" {
			result.TestError = res2.BootError
		}
		if res2.Report != nil {
			result.CandidateReproduced = true
			result.CandidateBugTitle = res2.Report.Title
			result.CandidateCrashReport = string(res2.Report.Report)
		}
		for _, rep := range res2.OtherReports {
			result.OtherCrashReports = append(result.OtherCrashReports, string(rep.Report))
		}
	}

	return result, nil
}
