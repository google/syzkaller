// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

// reproRunner is used to run reproducers on the base kernel to determine whether it is affected.
type reproRunner struct {
	done    chan reproRunnerResult
	running atomic.Int64
}

type reproRunnerResult struct {
	reproReport *report.Report
	crashReport *report.Report
	repro       *repro.Result
	fullRepro   bool // whether this was a full reproduction
}

const (
	// We want to avoid false positives as much as possible, so let's use
	// a stricter relibability cut-off than what's used inside pkg/repro.
	reliabilityCutOff = 0.4
	// 80% reliability x 3 runs is a 0.8% chance of false positives.
	// 6 runs at 40% reproducibility gives a ~4% false positive chance.
	reliabilityThreshold = 0.8
)

// Run executes the reproducer 3 times with slightly different options.
// The objective is to verify whether the bug triggered by the reproducer affects the base kernel.
// To avoid reporting false positives, the function does not require the kernel to crash with exactly
// the same crash title as in the original crash report. Any single crash is accepted.
// The result is sent back over the rr.done channel.
func (rr *reproRunner) Run(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool) {
	if r.Reliability < reliabilityCutOff {
		log.Logf(1, "%s: repro is too unreliable, skipping", r.Report.Title)
		return
	}
	needRuns := 3
	if r.Reliability < reliabilityThreshold {
		needRuns = 6
	}

	pool := k.Pool()
	cnt := int(rr.running.Add(1))
	pool.ReserveForRun(min(cnt, pool.Total()))
	defer func() {
		cnt := int(rr.running.Add(-1))
		pool.ReserveForRun(min(cnt, pool.Total()))
	}()

	ret := reproRunnerResult{reproReport: r.Report, repro: r, fullRepro: fullRepro}
	for doneRuns := 0; doneRuns < needRuns; {
		if ctx.Err() != nil {
			return
		}
		opts := r.Opts
		opts.Repeat = true
		if doneRuns%3 != 2 {
			// Two times out of 3, test with Threaded=true.
			// The third time we leave it as it was in the reproducer (in case it was important).
			opts.Threaded = true
		}
		var err error
		var result *instance.RunResult
		runErr := pool.Run(ctx, func(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
			var ret *instance.ExecProgInstance
			ret, err = instance.SetupExecProg(inst, k.Config(), k.Reporter(), nil)
			if err != nil {
				return
			}
			result, err = ret.RunSyzProg(instance.ExecParams{
				SyzProg:  r.Prog.Serialize(),
				Duration: max(r.Duration, time.Minute),
				Opts:     opts,
			})
		})
		logPrefix := fmt.Sprintf("attempt #%d to run %q on base", doneRuns, ret.reproReport.Title)
		if errors.Is(runErr, context.Canceled) {
			// Just exit without sending anything over the channel.
			log.Logf(1, "%s: aborting due to context cancelation", logPrefix)
			return
		}
		if runErr != nil || err != nil {
			log.Logf(1, "%s: skipping due to errors: %v / %v", logPrefix, runErr, err)
			continue
		}
		doneRuns++
		if result != nil && result.Report != nil {
			log.Logf(1, "%s: crashed with %s", logPrefix, result.Report.Title)
			ret.crashReport = result.Report
			break
		} else {
			log.Logf(1, "%s: did not crash", logPrefix)
		}
	}
	select {
	case rr.done <- ret:
	case <-ctx.Done():
	}
}

type runner interface {
	Run(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool)
	Results() <-chan reproRunnerResult
}

func (rr *reproRunner) Results() <-chan reproRunnerResult {
	return rr.done
}
