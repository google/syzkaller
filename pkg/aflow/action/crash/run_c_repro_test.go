// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/report"
	"github.com/stretchr/testify/require"
)

func TestRunCReproStraceDoesNotOverwriteCrashStatus(t *testing.T) {
	oldRunTest := runTest
	defer func() { runTest = oldRunTest }()

	args := RunCReproArgs{
		Target:          Target{TargetArch: "amd64"},
		FormattedReproC: "int main() { return 0; }",
		StraceBin:       "/bin/strace",
		NeedStrace:      true,
	}

	t.Run("strace-crash-discarded", func(t *testing.T) {
		var calls int
		runTest = func(ctx *aflow.Context, args ReproduceArgs, workdir string,
			collectCoverage bool) (RunTestResult, error) {
			calls++
			if !args.NeedStrace {
				return RunTestResult{
					ConsoleOutput: "[+] clean run output",
				}, nil
			}
			// Simulate strace -f triggering an unrelated ptrace KCSAN race on Run 2.
			return RunTestResult{
				ConsoleOutput: "strace log\nBUG: KCSAN: data-race in do_notify_parent_cldstop",
				Report: &report.Report{
					Title:  "KCSAN: data-race in do_notify_parent_cldstop / wait_consider_task",
					Report: []byte("BUG: KCSAN: data-race in do_notify_parent_cldstop"),
				},
				OtherReports: []*report.Report{
					{Title: "other strace crash", Report: []byte("other stack")},
				},
			}, nil
		}

		ctx := aflow.NewTestContext(t)
		res, err := RunCReproFunc(ctx, args)
		require.NoError(t, err)
		require.Equal(t, 2, calls)
		require.Equal(t, "[+] clean run output", res.ConsoleOutput)
		require.Empty(t, res.StraceOutput)
		require.False(t, res.CandidateReproduced)
		require.Empty(t, res.CandidateBugTitle)
		require.Empty(t, res.CandidateCrashReport)
		require.Empty(t, res.OtherCrashReports)
		require.Empty(t, res.TestError)
	})

	t.Run("strace-clean-preserved", func(t *testing.T) {
		var calls int
		runTest = func(ctx *aflow.Context, args ReproduceArgs, workdir string,
			collectCoverage bool) (RunTestResult, error) {
			calls++
			if !args.NeedStrace {
				return RunTestResult{
					ConsoleOutput: "[+] clean run output",
				}, nil
			}
			return RunTestResult{
				ConsoleOutput: "strace syscall log",
			}, nil
		}

		ctx := aflow.NewTestContext(t)
		res, err := RunCReproFunc(ctx, args)
		require.NoError(t, err)
		require.Equal(t, 2, calls)
		require.Equal(t, "[+] clean run output", res.ConsoleOutput)
		require.Equal(t, "strace syscall log", res.StraceOutput)
		require.False(t, res.CandidateReproduced)
	})
}

// TestRunCReproPassesTargetVMArch checks that TargetVMArch reaches the test config.
// Otherwise 386 jobs (which run on an amd64 kernel) look for syz-execprog in bin/linux_386.
func TestRunCReproPassesTargetVMArch(t *testing.T) {
	oldRunTest := runTest
	defer func() { runTest = oldRunTest }()

	var got TargetConfig
	runTest = func(ctx *aflow.Context, args ReproduceArgs, workdir string,
		collectCoverage bool) (RunTestResult, error) {
		got = args.TargetConfig
		return RunTestResult{}, nil
	}

	ctx := aflow.NewTestContext(t)
	_, err := RunCReproFunc(ctx, RunCReproArgs{
		Target:          Target{TargetArch: "386", TargetVMArch: "amd64"},
		FormattedReproC: "int main() { return 0; }",
	})
	require.NoError(t, err)
	require.Equal(t, "386", got.TargetArch)
	require.Equal(t, "amd64", got.VMArch())
}
