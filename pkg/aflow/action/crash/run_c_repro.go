// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"

	"github.com/google/syzkaller/pkg/aflow"
)

type RunCReproArgs struct {
	AgentName       string
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

var (
	RunCRepro = aflow.NewFuncAction("run-c-repro", RunCReproFunc)
	runTest   = RunTest
)

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
			AgentName:    args.AgentName,
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
	res1, err1 := runTest(ctx, reproduceArgs, workdir, false)
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

	// Run 2: with strace (only if first run didn't crash and didn't have boot error).
	// This pass is strictly for diagnostic strace logging. Do not overwrite Run 1's
	// crash/boot status, as attaching strace -f (ptrace) can trigger unrelated KCSAN
	// races (e.g. do_notify_parent_cldstop / wait_consider_task) or timeout slowdowns.
	// If Run 2 itself crashes or hits a boot/test error, also discard its ConsoleOutput
	// so we do not leak an unreported crash dump into StraceOutput.
	if !result.CandidateReproduced && result.TestError == "" && args.NeedStrace && args.StraceBin != "" {
		reproduceArgs.NeedStrace = true
		res2, err2 := runTest(ctx, reproduceArgs, workdir, false)
		if err2 != nil {
			return result, err2 // Return what we had from Run 1, plus the error.
		}
		if res2.Report == nil && res2.BootError == "" {
			result.StraceOutput = res2.ConsoleOutput
		}
	}

	return result, nil
}
