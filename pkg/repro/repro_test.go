// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initTest(t *testing.T) (*rand.Rand, int) {
	iters := 1000
	if testing.Short() {
		iters = 100
	}
	return rand.New(testutil.RandSource(t)), iters
}

func TestBisect(t *testing.T) {
	ctx := &reproContext{
		stats: new(Stats),
		logf:  t.Logf,
	}

	rd, iters := initTest(t)
	for range iters {
		var progs []*prog.LogEntry
		numTotal := rd.Intn(300)
		numGuilty := 0
		for range numTotal {
			var prog prog.LogEntry
			if rd.Intn(30) == 0 {
				prog.Proc = 42
				numGuilty++
			}
			progs = append(progs, &prog)
		}
		if numGuilty == 0 {
			var prog prog.LogEntry
			prog.Proc = 42
			progs = append(progs, &prog)
			numGuilty++
		}
		progs, _ = ctx.bisectProgs(progs, func(p []*prog.LogEntry) (bool, error) {
			guilty := 0
			for _, prog := range p {
				if prog.Proc == 42 {
					guilty++
				}
			}
			return guilty == numGuilty, nil
		})
		if numGuilty > 6 && len(progs) == 0 {
			// Bisection has been aborted.
			continue
		}
		if len(progs) != numGuilty {
			t.Fatalf("bisect test failed: wrong number of guilty progs: got: %v, want: %v", len(progs), numGuilty)
		}
		for _, prog := range progs {
			if prog.Proc != 42 {
				t.Fatalf("bisect test failed: wrong program is guilty: progs: %v", progs)
			}
		}
	}
}

func TestBisectWithFixed(t *testing.T) {
	ctx := &reproContext{
		stats: new(Stats),
		logf:  t.Logf,
		origExecutor: &report.ExecutorInfo{
			ExecID: 42,
		},
	}
	progs := []*prog.LogEntry{
		{ID: 10},
		{ID: 42},
		{ID: 20},
	}
	res, err := ctx.bisectProgs(progs, func(p []*prog.LogEntry) (bool, error) {
		for _, e := range p {
			if e.ID == 42 {
				return true, nil
			}
		}
		return false, nil
	})
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, 42, res[0].ID)
}

func TestSimplifies(t *testing.T) {
	opts := csource.Options{
		Threaded:     true,
		Repeat:       true,
		Procs:        10,
		Sandbox:      "namespace",
		NetInjection: true,
		NetDevices:   true,
		NetReset:     true,
		Cgroups:      true,
		UseTmpDir:    true,
		HandleSegv:   true,
	}
	var check func(opts csource.Options, i int)
	check = func(opts csource.Options, i int) {
		if err := opts.Check(targets.Linux); err != nil {
			t.Fatalf("opts are invalid: %v", err)
		}
		if i == len(cSimplifies) {
			return
		}
		check(opts, i+1)
		if cSimplifies[i](&opts) {
			check(opts, i+1)
		}
	}
	check(opts, 0)
}

type testExecInterface struct {
	// For now only do the simplest imitation.
	run func([]byte) (*instance.RunResult, error)
}

func (tei *testExecInterface) RunC(_ context.Context, p *prog.Prog, _ instance.RunOptions,
	_ instance.ExecutorLogger) (*instance.RunResult, error) {
	return tei.run(p.Serialize())
}

func (tei *testExecInterface) RunSyz(_ context.Context, syzProg []byte, _ instance.RunOptions,
	_ instance.ExecutorLogger) (*instance.RunResult, error) {
	return tei.run(syzProg)
}

func testEnvironment(t *testing.T, exec execInterface) Environment {
	mgrConfig := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetVMArch: targets.AMD64,
			SysTarget:    targets.Get(targets.Linux, targets.AMD64),
		},
		Sandbox: "namespace",
	}
	var err error
	mgrConfig.Target, err = prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := report.NewReporter(mgrConfig)
	if err != nil {
		t.Fatal(err)
	}
	return Environment{
		Config:   mgrConfig,
		Features: flatrpc.AllFeatures,
		Reporter: reporter,
		logf:     t.Logf,
		exec:     exec,
	}
}

func runTestRepro(t *testing.T, log string, exec execInterface) (*Result, *Stats, error) {
	return RunFromLog(context.Background(), []byte(log), testEnvironment(t, exec))
}

const testReproLog = `
2015/12/21 12:18:05 executing program 1:
getpid()
pause()
2015/12/21 12:18:10 executing program 2:
getpid()
getuid()
2015/12/21 12:18:15 executing program 1:
alarm(0x5)
pause()
2015/12/21 12:18:20 executing program 3:
alarm(0xa)
getpid()
`

// Only crash if `pause()` is followed by `alarm(0xa)`.
var testCrashCondition = regexp.MustCompile(`(?s)pause\(\).*alarm\(0xa\)`)

var (
	expectedReproducer = "pause()\nalarm(0xa)\n"
)

func fakeCrashResult(title string) *instance.RunResult {
	ret := &instance.RunResult{}
	if title != "" {
		ret.Report = &report.Report{
			Title: title,
			Type:  crash.TitleToType(title),
		}
	}
	return ret
}

func testExecRunner(log []byte) (*instance.RunResult, error) {
	crash := testCrashCondition.Match(log)
	if crash {
		return fakeCrashResult("crashed"), nil
	}
	return fakeCrashResult(""), nil
}

// Just a pkg/repro smoke test: check that we can extract a two-call reproducer.
// No focus on error handling and minor corner cases.
func TestPlainRepro(t *testing.T) {
	result, _, err := runTestRepro(t, testReproLog, &testExecInterface{
		run: testExecRunner,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expectedReproducer, string(result.Prog.Serialize()))
}

// There happen to be transient errors like ssh/scp connection failures.
// Ensure that the code just retries.
func TestVMErrorResilience(t *testing.T) {
	fail := false
	result, _, err := runTestRepro(t, testReproLog, &testExecInterface{
		run: func(log []byte) (*instance.RunResult, error) {
			fail = !fail
			if fail {
				return nil, fmt.Errorf("some random error")
			}
			return testExecRunner(log)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, `pause()
alarm(0xa)
`, string(result.Prog.Serialize()))
}

func TestTooManyErrors(t *testing.T) {
	counter := 0
	_, _, err := runTestRepro(t, testReproLog, &testExecInterface{
		run: func(log []byte) (*instance.RunResult, error) {
			counter++
			if counter%4 != 0 {
				return nil, fmt.Errorf("some random error")
			}
			return testExecRunner(log)
		},
	})
	if err == nil {
		t.Fatalf("expected an error")
	}
}

func TestProgConcatenation(t *testing.T) {
	// Since the crash condition is alarm() after pause(), the code
	// would have to work around the prog.MaxCall limitation.
	execLog := "2015/12/21 12:18:05 executing program 1:\n"
	for i := range prog.MaxCalls {
		if i == 10 {
			execLog += "pause()\n"
		} else {
			execLog += "getpid()\n"
		}
	}
	execLog += "2015/12/21 12:18:10 executing program 2:\n"
	for i := range prog.MaxCalls {
		if i == 10 {
			execLog += "alarm(0xa)\n"
		} else {
			execLog += "getpid()\n"
		}
	}
	result, _, err := runTestRepro(t, execLog, &testExecInterface{
		run: testExecRunner,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, `pause()
alarm(0xa)
`, string(result.Prog.Serialize()))
}

func TestFlakyCrashes(t *testing.T) {
	t.Parallel()
	// A single flaky crash may divert the whole process.
	// Let's check if the Reliability score provides a reasonable cut-off for such fake results.

	r := rand.New(testutil.RandSource(t))
	iters := 250

	success := 0
	for range iters {
		counter, lastFake := 0, 0
		result, _, err := runTestRepro(t, testReproLog, &testExecInterface{
			run: func(log []byte) (*instance.RunResult, error) {
				// Throw in a fake crash with 5% probability,
				// but not more often than once in 10 consecutive runs.
				counter++
				if r.Intn(20) == 0 && counter-lastFake >= 10 {
					lastFake = counter
					return fakeCrashResult("flaky crash"), nil
				}
				return testExecRunner(log)
			},
		})
		// It should either find nothing (=> validation worked) or find the exact reproducer.
		require.NoError(t, err)
		if result == nil {
			continue
		}
		success++
		assert.Equal(t, expectedReproducer, string(result.Prog.Serialize()), "reliability: %.2f", result.Reliability)
	}

	// There was no deep reasoning behind the success rate. It's not 100% due to flakiness,
	// but there should still be some significant number of success cases.
	assert.Greater(t, success, iters/3*2, "must succeed >2/3 of cases")
}

func BenchmarkCalculateReliability(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for base := 0.0; base < 1.0; base += 0.1 {
		b.Run(fmt.Sprintf("p=%.2f", base), func(b *testing.B) {
			if b.N == 0 {
				return
			}
			neededRuns := make([]int, 0, b.N)
			reliability := make([]float64, 0, b.N)

			b.ResetTimer()
			for range b.N {
				runs := 0
				ret, err := calculateReliability(func() (bool, error) {
					runs++
					return r.Float64() < base, nil
				})
				require.NoError(b, err)
				neededRuns = append(neededRuns, runs)
				reliability = append(reliability, ret)
			}
			b.StopTimer()

			sort.Ints(neededRuns)
			b.ReportMetric(float64(neededRuns[len(neededRuns)/2]), "runs")

			sort.Float64s(reliability)
			b.ReportMetric(reliability[len(reliability)/10], "p10")
			b.ReportMetric(reliability[len(reliability)/2], "median")
			b.ReportMetric(reliability[len(reliability)*9/10], "p90")
		})
	}
}

func TestBrokenCompilerRepro(t *testing.T) {
	sysTarget := *targets.Get(targets.Linux, targets.AMD64)
	sysTarget.BrokenCompiler = "some compiler error"

	mgrConfig := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetVMArch: targets.AMD64,
			SysTarget:    &sysTarget,
		},
		Sandbox: "namespace",
	}
	var err error
	mgrConfig.Target, err = prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	reporter, err := report.NewReporter(mgrConfig)
	require.NoError(t, err)
	env := Environment{
		Config:   mgrConfig,
		Features: flatrpc.AllFeatures,
		Fast:     false,
		Reporter: reporter,
		logf:     t.Logf,
		exec: &testExecInterface{
			run: testExecRunner,
		},
	}

	result, _, err := RunFromLog(context.Background(), []byte(testReproLog), env)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, false, result.CRepro, "C repro should have been skipped")
}

func TestAvoidLostConnection(t *testing.T) {
	const log = `
2015/12/21 12:18:05 executing program 1:
pause()
2015/12/21 12:18:10 executing program 2:
alarm(0xa)
`
	panicLog := log + "\npanic: some error\n"

	result, _, err := runTestRepro(t, panicLog, &testExecInterface{
		run: func(p []byte) (*instance.RunResult, error) {
			if strings.Contains(string(p), "alarm(0xa)") && !strings.Contains(string(p), "pause()") {
				// alarm(0xa) alone causes a system failure.
				return &instance.RunResult{
					Report: &report.Report{
						Title: "lost connection to test machine",
						Type:  crash.LostConnection,
					},
				}, nil
			}
			if strings.Contains(string(p), "pause()") && strings.Contains(string(p), "alarm(0xa)") {
				// The combination causes the target bug.
				return fakeCrashResult("panic: some error"), nil
			}
			return fakeCrashResult(""), nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "pause()\nalarm(0xa)\n", string(result.Prog.Serialize()))
}

func TestReproDuration(t *testing.T) {
	const progTimeout = 5 * time.Second
	tests := []struct {
		name            string
		baseTimeout     time.Duration
		crashedDuration time.Duration
		want            time.Duration
	}{
		{
			name:            "fast crash below progTimeout",
			baseTimeout:     6 * time.Minute,
			crashedDuration: 500 * time.Millisecond,
			want:            10 * time.Second,
		},
		{
			name:            "normal crash scaled by 2",
			baseTimeout:     6 * time.Minute,
			crashedDuration: 20 * time.Second,
			want:            40 * time.Second,
		},
		{
			name:            "slow crash capped at baseTimeout",
			baseTimeout:     100 * time.Second,
			crashedDuration: 80 * time.Second,
			want:            100 * time.Second,
		},
		{
			name:            "tight baseTimeout limit",
			baseTimeout:     5 * time.Second,
			crashedDuration: 2 * time.Second,
			want:            5 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reproDuration(tt.baseTimeout, tt.crashedDuration, progTimeout)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDivergentCrash(t *testing.T) {
	const log = `
2015/12/21 12:18:05 executing program 1:
alarm(0xa)
2015/12/21 12:18:10 executing program 2:
pause()
`
	var divergentReports []*report.Report
	env := testEnvironment(t, &testExecInterface{
		run: func(p []byte) (*instance.RunResult, error) {
			if strings.Contains(string(p), "pause()") {
				return fakeCrashResult("WARNING: unrelated warning"), nil
			}
			if strings.Contains(string(p), "alarm(0xa)") {
				return fakeCrashResult("panic: target error"), nil
			}
			return fakeCrashResult(""), nil
		},
	})
	env.OnDivergentCrash = func(rep *report.Report) {
		divergentReports = append(divergentReports, rep)
	}
	target := &report.Report{
		Title:  "panic: target error",
		Output: []byte(log),
	}
	result, _, err := Run(context.Background(), target, env)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "panic: target error", result.Report.Title)
	require.Equal(t, "alarm(0xa)\n", string(result.Prog.Serialize()))

	require.Len(t, divergentReports, 1)
	require.Equal(t, "WARNING: unrelated warning", divergentReports[0].Title)
	require.Contains(t, string(divergentReports[0].Output), "pause()")
}

func TestLogWithoutReport(t *testing.T) {
	const log = `
2015/12/21 12:18:05 executing program 1:
alarm(0xa)
2015/12/21 12:18:10 executing program 2:
pause()
`
	var divergentReports []*report.Report
	env := testEnvironment(t, &testExecInterface{
		run: func(p []byte) (*instance.RunResult, error) {
			if strings.Contains(string(p), "pause()") {
				return fakeCrashResult("WARNING: first crash"), nil
			}
			return fakeCrashResult(""), nil
		},
	})
	env.OnDivergentCrash = func(rep *report.Report) {
		divergentReports = append(divergentReports, rep)
	}
	result, _, err := RunFromLog(context.Background(), []byte(log), env)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "WARNING: first crash", result.Report.Title)
	require.Equal(t, "pause()\n", string(result.Prog.Serialize()))
	require.Empty(t, divergentReports)
}

// Verify that if Executor.ExecID is present in the crash report, that program is tested
// first rather than the last entry of each proc.
func TestCrashExecutorPriority(t *testing.T) {
	const log = `
2015/12/21 12:18:05 executing program 1 (id=100):
alarm(0xa)
2015/12/21 12:18:10 executing program 2 (id=200):
pause()
`
	target := &report.Report{
		Title:  "panic: target error",
		Type:   crash.TitleToType("panic: target error"),
		Output: []byte(log),
		Executor: &report.ExecutorInfo{
			ExecID: 100,
		},
	}
	var testedProgs []string
	result, _, err := Run(context.Background(), target, testEnvironment(t, &testExecInterface{
		run: func(p []byte) (*instance.RunResult, error) {
			testedProgs = append(testedProgs, string(p))
			if strings.Contains(string(p), "alarm(0xa)") {
				return fakeCrashResult("panic: target error"), nil
			}
			return fakeCrashResult(""), nil
		},
	}))
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "alarm(0xa)\n", string(result.Prog.Serialize()))
	require.NotEmpty(t, testedProgs)
	require.Contains(t, testedProgs[0], "alarm(0xa)")
}

// Verify that during the validation phase, title switches of the same bug type are accepted
// towards reliability, while low-priority failures and different bug types are ignored.
func TestValidationRelaxedMatching(t *testing.T) {
	ctx := &reproContext{
		targetReport: &report.Report{
			Title: "WARNING in sock_init_data",
			Type:  crash.Warning,
		},
		stats:      new(Stats),
		validating: true,
	}
	// Title variation of the same bug type is accepted.
	v, err := ctx.getVerdict(func() (*instance.RunResult, error) {
		return &instance.RunResult{
			Report: &report.Report{
				Title: "WARNING in sock_setsockopt",
				Type:  crash.Warning,
			},
		}, nil
	}, nil, false)
	require.NoError(t, err)
	require.True(t, v.Crashed)

	// Downgrade to low-priority failure (e.g. lost connection) is rejected.
	v, err = ctx.getVerdict(func() (*instance.RunResult, error) {
		return &instance.RunResult{
			Report: &report.Report{
				Title: "lost connection to test machine",
				Type:  crash.LostConnection,
			},
		}, nil
	}, nil, false)
	require.NoError(t, err)
	require.False(t, v.Crashed)

	// Different bug type (e.g. BUG vs Warning) is rejected.
	v, err = ctx.getVerdict(func() (*instance.RunResult, error) {
		return &instance.RunResult{
			Report: &report.Report{
				Title: "BUG: unable to handle kernel paging request",
				Type:  crash.Bug,
			},
		}, nil
	}, nil, false)
	require.NoError(t, err)
	require.False(t, v.Crashed)
}
