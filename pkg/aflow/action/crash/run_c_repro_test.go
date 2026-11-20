// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
	"github.com/stretchr/testify/assert"
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
			opts RunTestOpts) (RunTestResult, error) {
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
			opts RunTestOpts) (RunTestResult, error) {
			calls++
			if !args.NeedStrace {
				assert.Equal(t, RunTestOpts{}, opts)
				return RunTestResult{
					ConsoleOutput: "[+] clean run output",
				}, nil
			}
			// The strace pass is diagnostics-only: a single run, no retries.
			assert.Equal(t, RunTestOpts{MaxTotalRuns: 1}, opts)
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

	infraErrors := map[string]error{
		"strace-infra-error-ignored": fmt.Errorf("failed to collect 1 valid runs within 3 total attempts. "+
			"Last infra error: %w", &instance.TestError{Infra: true, Title: "ZONE_RESOURCE_POOL_EXHAUSTED"}),
		"strace-too-many-infra-errors-ignored": fmt.Errorf("%w: last infra error: %w",
			instance.ErrTooManyInfraErrors, errors.New("unknown error")),
		"strace-vm-infra-error-ignored": fmt.Errorf("failed to create VM pool: %w",
			vm.InfraError{Title: "ZONE_RESOURCE_POOL_EXHAUSTED"}),
	}
	for name, infraErr := range infraErrors {
		t.Run(name, func(t *testing.T) {
			var calls, straceCalls int
			runTest = func(ctx *aflow.Context, args ReproduceArgs, workdir string,
				opts RunTestOpts) (RunTestResult, error) {
				calls++
				if !args.NeedStrace {
					return RunTestResult{
						ConsoleOutput: "[+] clean run output",
					}, nil
				}
				straceCalls++
				return RunTestResult{}, infraErr
			}

			ctx := aflow.NewTestContext(t)
			res, err := RunCReproFunc(ctx, args)
			require.NoError(t, err)
			assert.Equal(t, 2, calls)
			assert.Equal(t, 1, straceCalls)
			assert.Equal(t, "[+] clean run output", res.ConsoleOutput)
			assert.Empty(t, res.StraceOutput)
		})
	}

	t.Run("strace-other-error-propagated", func(t *testing.T) {
		var calls, straceCalls int
		runTest = func(ctx *aflow.Context, args ReproduceArgs, workdir string,
			opts RunTestOpts) (RunTestResult, error) {
			calls++
			if !args.NeedStrace {
				return RunTestResult{
					ConsoleOutput: "[+] clean run output",
				}, nil
			}
			straceCalls++
			return RunTestResult{}, errors.New("failed to build config")
		}

		ctx := aflow.NewTestContext(t)
		res, err := RunCReproFunc(ctx, args)
		assert.EqualError(t, err, "failed to build config")
		assert.Equal(t, 2, calls)
		assert.Equal(t, 1, straceCalls)
		assert.Equal(t, "[+] clean run output", res.ConsoleOutput)
	})
}

// TestRunCReproPassesTargetVMArch checks that TargetVMArch reaches the test config.
// Otherwise 386 jobs (which run on an amd64 kernel) look for syz-execprog in bin/linux_386.
func TestRunCReproPassesTargetVMArch(t *testing.T) {
	oldRunTest := runTest
	defer func() { runTest = oldRunTest }()

	var got TargetConfig
	runTest = func(ctx *aflow.Context, args ReproduceArgs, workdir string,
		opts RunTestOpts) (RunTestResult, error) {
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

func TestRunCReproPrintedByProgram(t *testing.T) {
	oldRunTest := runTest
	defer func() { runTest = oldRunTest }()

	output := []byte(`[   80.000000][ T1] loop0: detected capacity change
[+] Starting reproducer for kernel BUG in foo...
[   83.000000][ T2] kernel BUG at fs/super.c:733!
`)
	printed := &report.Report{
		Title:    "kernel BUG in foo...",
		Report:   []byte("[+] Starting reproducer for kernel BUG in foo..."),
		Output:   output,
		StartPos: bytes.Index(output, []byte("[+] Starting")),
		EndPos:   len(output),
	}
	kernel := &report.Report{
		Title:    "kernel BUG in generic_shutdown_super",
		Report:   []byte("kernel BUG at fs/super.c:733!"),
		Output:   output,
		StartPos: bytes.Index(output, []byte("[   83")),
		EndPos:   len(output),
	}
	assert.True(t, printedByProgram(printed))
	assert.False(t, printedByProgram(kernel))
	// Synthetic fallback reports (e.g. lost connection / timeout) have no Report and StartPos=0.
	assert.False(t, printedByProgram(&report.Report{
		Title:  "lost connection to test machine",
		Output: output,
	}))
	// Mid-line "[1.0]" in program output is not a kernel timestamp.
	midlineOutput := []byte(`[   80.000000][ T1] loop0: detected capacity change
[+] step [1.0] kernel BUG in foo...
`)
	assert.True(t, printedByProgram(&report.Report{
		Title:    "kernel BUG in foo...",
		Report:   []byte("[+] step [1.0] kernel BUG in foo..."),
		Output:   midlineOutput,
		StartPos: bytes.Index(midlineOutput, []byte("[+] step")),
	}))
	// Without timestamps in the console output we can't tell, so the report is trusted.
	assert.False(t, printedByProgram(&report.Report{
		Report:   printed.Report,
		Output:   []byte("[+] Starting reproducer for kernel BUG in foo...\n"),
		StartPos: 0,
	}))

	t.Run("printed-and-kernel-crash", func(t *testing.T) {
		runTest = func(ctx *aflow.Context, args ReproduceArgs, workdir string,
			opts RunTestOpts) (RunTestResult, error) {
			return RunTestResult{
				ConsoleOutput: string(output),
				Report:        printed,
				OtherReports:  []*report.Report{printed, kernel},
			}, nil
		}
		ctx := aflow.NewTestContext(t)
		res, err := RunCReproFunc(ctx, RunCReproArgs{
			Target:          Target{TargetArch: "amd64"},
			FormattedReproC: "int main() { return 0; }",
		})
		require.NoError(t, err)
		assert.True(t, res.CandidateReproduced)
		assert.Equal(t, "kernel BUG in generic_shutdown_super", res.CandidateBugTitle)
		assert.Empty(t, res.OtherCrashReports)
		assert.Contains(t, res.ConsoleOutput, `detected as "kernel BUG in foo..."`)
		assert.NotContains(t, res.ConsoleOutput, `"kernel BUG in foo...", "kernel BUG in foo..."`)
	})

	t.Run("only-printed-marker", func(t *testing.T) {
		runTest = func(ctx *aflow.Context, args ReproduceArgs, workdir string,
			opts RunTestOpts) (RunTestResult, error) {
			return RunTestResult{ConsoleOutput: string(output), Report: printed}, nil
		}
		ctx := aflow.NewTestContext(t)
		res, err := RunCReproFunc(ctx, RunCReproArgs{
			Target:          Target{TargetArch: "amd64"},
			FormattedReproC: "int main() { return 0; }",
		})
		require.NoError(t, err)
		assert.False(t, res.CandidateReproduced)
		assert.Empty(t, res.CandidateBugTitle)
	})

	t.Run("strace-with-printed-marker", func(t *testing.T) {
		for _, straceReport := range []*report.Report{printed, kernel} {
			runTest = func(ctx *aflow.Context, args ReproduceArgs, workdir string,
				opts RunTestOpts) (RunTestResult, error) {
				if args.NeedStrace {
					return RunTestResult{ConsoleOutput: "strace output", Report: straceReport}, nil
				}
				return RunTestResult{ConsoleOutput: string(output), Report: printed}, nil
			}
			ctx := aflow.NewTestContext(t)
			res, err := RunCReproFunc(ctx, RunCReproArgs{
				Target:          Target{TargetArch: "amd64"},
				FormattedReproC: "int main() { return 0; }",
				StraceBin:       "/bin/strace",
				NeedStrace:      true,
			})
			require.NoError(t, err)
			assert.False(t, res.CandidateReproduced)
			if straceReport == printed {
				assert.Equal(t, "strace output", res.StraceOutput)
			} else {
				assert.Empty(t, res.StraceOutput)
			}
		}
	})
}
