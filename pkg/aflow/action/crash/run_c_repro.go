// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
)

type RunCReproArgs struct {
	Target
	AgentName       string
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
			Target:       args.Target,
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
	res1, err1 := runTest(ctx, reproduceArgs, workdir, RunTestOpts{})
	if err1 != nil {
		return RunCReproResult{}, err1
	}

	result := RunCReproResult{
		ConsoleOutput: res1.ConsoleOutput,
		TestError:     res1.BootError,
	}
	kernelReps, printedReps := splitReports(res1)
	if len(printedReps) > 0 {
		var titles []string
		for _, rep := range printedReps {
			title := fmt.Sprintf("%q", rep.Title)
			if !slices.Contains(titles, title) {
				titles = append(titles, title)
			}
		}
		result.ConsoleOutput += fmt.Sprintf("\nNOTE: the program printed a kernel crash marker"+
			" (detected as %s), which is not a kernel crash and caused the VM monitor to stop"+
			" the run early. Tell the generator not to print bug titles or kernel crash"+
			" markers in the program output.\n", strings.Join(titles, ", "))
	}
	if len(kernelReps) > 0 {
		result.CandidateReproduced = true
		result.CandidateBugTitle = kernelReps[0].Title
		result.CandidateCrashReport = string(kernelReps[0].Report)
		for _, rep := range kernelReps[1:] {
			result.OtherCrashReports = append(result.OtherCrashReports, string(rep.Report))
		}
	}

	// Run 2: with strace (only if first run didn't crash and didn't have boot error).
	// This pass is strictly for diagnostic strace logging. Do not overwrite Run 1's
	// crash/boot status, as attaching strace -f (ptrace) can trigger unrelated KCSAN
	// races (e.g. do_notify_parent_cldstop / wait_consider_task) or timeout slowdowns.
	// If Run 2 itself has a kernel crash or hits a boot/test error (markers printed by
	// the program don't count as crashes), also discard its ConsoleOutput so we do not
	// leak an unreported crash dump into StraceOutput.
	if !result.CandidateReproduced && result.TestError == "" && args.NeedStrace && args.StraceBin != "" {
		reproduceArgs.NeedStrace = true
		// Strace output is only used for diagnostics, one run is enough.
		// It's also optional, so don't spend time retrying infra errors.
		res2, err2 := runTest(ctx, reproduceArgs, workdir, RunTestOpts{MaxTotalRuns: 1})
		if isInfraError(err2) {
			// We failed to get a VM. Don't fail the action, Run 1 results are still valid.
			log.Logf(0, "failed to collect strace output: %v", err2)
			return result, nil
		}
		if err2 != nil {
			return result, err2 // Return what we had from Run 1, plus the error.
		}
		if kernelReps, _ := splitReports(res2); len(kernelReps) == 0 && res2.BootError == "" {
			result.StraceOutput = res2.ConsoleOutput
		}
	}

	return result, nil
}

// splitReports splits the crash reports of a test run into the reports triggered by the kernel
// and the reports triggered by the program printing kernel crash markers.
func splitReports(res RunTestResult) ([]*report.Report, []*report.Report) {
	var kernel, printed []*report.Report
	for _, rep := range append([]*report.Report{res.Report}, res.OtherReports...) {
		switch {
		case rep == nil:
		case printedByProgram(rep):
			printed = append(printed, rep)
		default:
			kernel = append(kernel, rep)
		}
	}
	return kernel, printed
}

// consoleTimestampRe matches kernel console timestamps (e.g. "[   83.153006]").
var consoleTimestampRe = regexp.MustCompile(`(?m)^(?:\<[0-9]+\>)?\[ *[0-9]+\.[0-9]+\]`)

// printedByProgram returns whether the crash report was triggered by a line printed by the program
// itself (e.g. the program printed the bug title), rather than by the kernel: kernel console lines
// have timestamps, while the program output doesn't. The check is done only if the console output
// has timestamps at all. Note that the VM monitor still stops the run early when it sees the
// printed marker, so the generator is also instructed not to print crash markers.
func printedByProgram(rep *report.Report) bool {
	if len(rep.Report) == 0 || rep.StartPos < 0 || rep.StartPos >= len(rep.Output) {
		return false
	}
	start := bytes.LastIndexByte(rep.Output[:rep.StartPos], '\n') + 1
	end := len(rep.Output)
	if pos := bytes.IndexByte(rep.Output[rep.StartPos:], '\n'); pos != -1 {
		end = rep.StartPos + pos
	}
	return !consoleTimestampRe.Match(rep.Output[start:end]) && consoleTimestampRe.Match(rep.Output)
}

// isInfraError checks whether the error was caused by the infrastructure rather than by the kernel.
func isInfraError(err error) bool {
	if errors.Is(err, instance.ErrTooManyInfraErrors) {
		return true
	}
	if _, ok := errors.AsType[vm.InfraError](err); ok {
		return true
	}
	testErr, ok := errors.AsType[*instance.TestError](err)
	return ok && testErr.Infra
}
