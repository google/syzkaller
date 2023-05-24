// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"math/rand"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func initTest(t *testing.T) (*rand.Rand, int) {
	iters := 1000
	if testing.Short() {
		iters = 100
	}
	return rand.New(testutil.RandSource(t)), iters
}

func TestBisect(t *testing.T) {
	ctx := &context{
		stats: new(Stats),
	}

	rd, iters := initTest(t)
	for n := 0; n < iters; n++ {
		var progs []*prog.LogEntry
		numTotal := rd.Intn(300)
		numGuilty := 0
		for i := 0; i < numTotal; i++ {
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
		if numGuilty > 8 && len(progs) == 0 {
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
		Repro:        true,
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

func generateTestInstances(ctx *context, count int, execInterface execInterface) {
	for i := 0; i < count; i++ {
		ctx.bootRequests <- i
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for vmIndex := range ctx.bootRequests {
			ctx.instances <- &reproInstance{execProg: execInterface, index: vmIndex}
		}
	}()
	wg.Wait()
}

type testExecInterface struct {
	t *testing.T
	// For now only do the simplest imitation.
	run func([]byte) (*instance.RunResult, error)
}

func (tei *testExecInterface) Close() {}

func (tei *testExecInterface) RunCProg(p *prog.Prog, duration time.Duration,
	opts csource.Options) (*instance.RunResult, error) {
	return tei.RunSyzProg(p.Serialize(), duration, opts)
}

func (tei *testExecInterface) RunSyzProg(syzProg []byte, duration time.Duration,
	opts csource.Options) (*instance.RunResult, error) {
	return tei.run(syzProg)
}

func prepareTestCtx(t *testing.T, log string) *context {
	mgrConfig := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetVMArch: targets.AMD64,
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
	ctx, err := prepareCtx([]byte(log), mgrConfig, nil, reporter, 3)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
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

// Just a pkg/repro smoke test: check that we can extract a two-call reproducer.
// No focus on error handling and minor corner cases.
func TestPlainRepro(t *testing.T) {
	ctx := prepareTestCtx(t, testReproLog)
	// Only crash if `pause()` is followed by `alarm(0xa)`.
	var match = regexp.MustCompile(`(?s)pause\(\).*alarm\(0xa\)`)
	go generateTestInstances(ctx, 3, &testExecInterface{
		t: t,
		run: func(log []byte) (*instance.RunResult, error) {
			crash := match.Match(log)
			if crash {
				ret := &instance.RunResult{}
				ret.Report = &report.Report{
					Title: `some crash`,
				}
				return ret, nil
			}
			return &instance.RunResult{}, nil
		},
	})
	result, _, err := ctx.run()
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(`pause()
alarm(0xa)
`, string(result.Prog.Serialize())); diff != "" {
		t.Fatal(diff)
	}
}
