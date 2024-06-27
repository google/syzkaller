// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type job interface {
	run(fuzzer *Fuzzer)
}

func genProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.target.Generate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable())
	return &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecGenerate,
	}
}

func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.Config.Corpus.ChooseProgram(rnd)
	if p == nil {
		return nil
	}
	newP := p.Clone()
	newP.Mutate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable(),
		fuzzer.Config.NoMutateCalls,
		fuzzer.Config.Corpus.Programs(),
	)
	return &queue.Request{
		Prog:     newP,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecFuzz,
	}
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p      *prog.Prog
	flags  ProgFlags
	fuzzer *Fuzzer
	queue  queue.Executor
	// Set of calls that gave potential new coverage.
	calls map[int]*triageCall
}

type triageCall struct {
	errno     int32
	newSignal signal.Signal

	// Filled after deflake:
	signals         [deflakeNeedRuns]signal.Signal
	stableSignal    signal.Signal
	newStableSignal signal.Signal
	cover           cover.Cover
	rawCover        []uint64
}

// As demonstrated in #4639, programs reproduce with a very high, but not 100% probability.
// The triage algorithm must tolerate this, so let's pick the signal that is common
// to 3 out of 5 runs.
// By binomial distribution, a program that reproduces 80% of time will pass deflake()
// with a 94% probability. If it reproduces 90% of time, it passes in 99% of cases.
const (
	deflakeNeedRuns      = 3
	deflakeMaxRuns       = 5
	deflakeMaxCorpusRuns = 20
)

func (job *triageJob) execute(req *queue.Request, flags ProgFlags) *queue.Result {
	req.Important = true // All triage executions are important.
	return job.fuzzer.executeWithFlags(job.queue, req, flags)
}

func (job *triageJob) run(fuzzer *Fuzzer) {
	fuzzer.statNewInputs.Add(1)
	job.fuzzer = fuzzer

	// Compute input coverage and non-flaky signal for minimization.
	stop := job.deflake(job.execute)
	if stop {
		return
	}
	for call, info := range job.calls {
		job.handleCall(call, info)
	}
}

func (job *triageJob) handleCall(call int, info *triageCall) {
	if info.newStableSignal.Empty() {
		return
	}

	p := job.p.Clone()
	if job.flags&ProgMinimized == 0 {
		p, call = job.minimize(call, info)
		if p == nil {
			return
		}
	}
	callName := p.CallName(call)
	if !job.fuzzer.Config.NewInputFilter(callName) {
		return
	}
	if job.flags&ProgSmashed == 0 {
		job.fuzzer.startJob(job.fuzzer.statJobsSmash, &smashJob{
			exec: job.fuzzer.smashQueue,
			p:    p.Clone(),
		})
		if job.fuzzer.Config.Comparisons && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsHints, &hintsJob{
				exec: job.fuzzer.hintsQueue.Append(),
				p:    p.Clone(),
				call: call,
			})
		}
		if job.fuzzer.Config.FaultInjection && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsFaultInjection, &faultInjectionJob{
				exec: job.fuzzer.hintsQueue.Append(),
				p:    p.Clone(),
				call: call,
			})
		}
	}
	job.fuzzer.Logf(2, "added new input for %v to the corpus: %s", callName, p)
	input := corpus.NewInput{
		Prog:     p,
		Call:     call,
		Signal:   info.stableSignal,
		Cover:    info.cover.Serialize(),
		RawCover: info.rawCover,
	}
	job.fuzzer.Config.Corpus.Save(input)
}

func (job *triageJob) deflake(exec func(*queue.Request, ProgFlags) *queue.Result) (stop bool) {
	prevTotalNewSignal := 0
	for run := 1; ; run++ {
		totalNewSignal := 0
		indices := make([]int, 0, len(job.calls))
		for call, info := range job.calls {
			indices = append(indices, call)
			totalNewSignal += len(info.newSignal)
		}
		// For fuzzing programs we stop if we already have the right deflaked signal for all calls,
		// or there's no chance to get coverage common to needRuns for all calls.
		if job.flags&ProgFromCorpus == 0 {
			if run >= deflakeMaxRuns {
				break
			}
			haveSignal, noChance := true, true
			for _, call := range job.calls {
				if !call.newSignal.IntersectsWith(call.signals[deflakeNeedRuns-1]) {
					haveSignal = false
				}
				if left := deflakeMaxRuns - run; left >= deflakeNeedRuns ||
					call.newSignal.IntersectsWith(call.signals[deflakeNeedRuns-left-1]) {
					noChance = false
				}
			}
			if haveSignal || noChance {
				break
			}
		} else if run >= deflakeMaxCorpusRuns ||
			run >= deflakeMaxRuns && prevTotalNewSignal == totalNewSignal {
			// For programs from the corpus we use a different condition b/c we want to extract
			// as much flaky signal from them as possible. They have large coverage and run
			// in the beginning, gathering flaky signal on them allows to grow max signal quickly
			// and avoid lots of useless executions later. Any bit of flaky coverage discovered
			// later will lead to triage, and if we are unlucky to conclude it's stable also
			// to minimization+smash+hints (potentially thousands of runs).
			// So we run them at least 5 times, or while we are still getting any new signal.
			break
		}
		prevTotalNewSignal = totalNewSignal
		result := exec(&queue.Request{
			Prog:            job.p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			ReturnAllSignal: indices,
			Stat:            job.fuzzer.statExecTriage,
		}, progInTriage)
		if result.Stop() {
			return true
		}
		if result.Info == nil {
			continue // the program has failed
		}
		deflakeCall := func(call int, res *flatrpc.CallInfo) {
			info := job.calls[call]
			if info == nil {
				job.fuzzer.triageProgCall(job.p, res, call, &job.calls)
				info = job.calls[call]
			}
			if info == nil || res == nil {
				return
			}
			if len(info.rawCover) == 0 && job.fuzzer.Config.FetchRawCover {
				info.rawCover = res.Cover
			}
			// Since the signal is frequently flaky, we may get some new new max signal.
			// Merge it into the new signal we are chasing.
			// Most likely we won't conclude it's stable signal b/c we already have at least one
			// initial run w/o this signal, so if we exit after 3 (deflakeNeedRuns) runs,
			// it won't be stable. However, it's still possible if we do more than deflakeNeedRuns runs.
			// But also we already observed it and we know it's flaky, so at least doing
			// cover.addRawMaxSignal for it looks useful.
			prio := signalPrio(job.p, res, call)
			newMaxSignal := job.fuzzer.Cover.addRawMaxSignal(res.Signal, prio)
			info.newSignal.Merge(newMaxSignal)
			info.cover.Merge(res.Cover)
			thisSignal := signal.FromRaw(res.Signal, prio)
			for j := len(info.signals) - 1; j > 0; j-- {
				intersect := info.signals[j-1].Intersection(thisSignal)
				info.signals[j].Merge(intersect)
			}
			info.signals[0].Merge(thisSignal)
		}
		for i, callInfo := range result.Info.Calls {
			deflakeCall(i, callInfo)
		}
		deflakeCall(-1, result.Info.Extra)
	}
	for _, info := range job.calls {
		info.stableSignal = info.signals[deflakeNeedRuns-1]
		info.newStableSignal = info.newSignal.Intersection(info.stableSignal)
	}
	return false
}

func (job *triageJob) minimize(call int, info *triageCall) (*prog.Prog, int) {
	const minimizeAttempts = 3
	stop := false
	p, call := prog.Minimize(job.p, call, prog.MinimizeParams{},
		func(p1 *prog.Prog, call1 int) bool {
			if stop {
				return false
			}
			for i := 0; i < minimizeAttempts; i++ {
				result := job.execute(&queue.Request{
					Prog:            p1,
					ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
					ReturnAllSignal: []int{call1},
					Stat:            job.fuzzer.statExecMinimize,
				}, 0)
				if result.Stop() {
					stop = true
					return false
				}
				if !reexecutionSuccess(result.Info, info.errno, call1) {
					// The call was not executed or failed.
					continue
				}
				thisSignal := getSignalAndCover(p1, result.Info, call1)
				if info.newStableSignal.Intersection(thisSignal).Len() == info.newStableSignal.Len() {
					return true
				}
			}
			return false
		})
	if stop {
		return nil, 0
	}
	return p, call
}

func reexecutionSuccess(info *flatrpc.ProgInfo, oldErrno int32, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldErrno == 0 && info.Calls[call].Error != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return info.Extra != nil && len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *flatrpc.ProgInfo, call int) signal.Signal {
	inf := info.Extra
	if call != -1 {
		inf = info.Calls[call]
	}
	if inf == nil {
		return nil
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call))
}

type smashJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
}

func (job *smashJob) run(fuzzer *Fuzzer) {
	fuzzer.Logf(2, "smashing the program %s (call=%d):", job.p, job.call)

	const iters = 25
	rnd := fuzzer.rand()
	for i := 0; i < iters; i++ {
		p := job.p.Clone()
		p.Mutate(rnd, prog.RecommendedCalls,
			fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls,
			fuzzer.Config.Corpus.Programs())
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:     fuzzer.statExecSmash,
		})
		if result.Stop() {
			return
		}
	}
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}

type faultInjectionJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
}

func (job *faultInjectionJob) run(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		fuzzer.Logf(2, "injecting fault into call %v, step %v",
			job.call, nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog: newProg,
			Stat: fuzzer.statExecFaultInject,
		})
		if result.Stop() {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&flatrpc.CallFlagFaultInjected == 0 {
			break
		}
	}
}

type hintsJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program twice to get comparisons from KCOV.
	// The second execution lets us filter out flaky values, which seem to constitute ~30-40%.
	p := job.p

	var comps prog.CompMap
	for i := 0; i < 2; i++ {
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectComps),
			Stat:     fuzzer.statExecSeed,
		})
		if result.Stop() || result.Info == nil {
			return
		}
		got := make(prog.CompMap)
		for _, cmp := range result.Info.Calls[job.call].Comps {
			got.AddComp(cmp.Op1, cmp.Op2)
		}
		if len(got) == 0 {
			return
		}
		if i == 0 {
			comps = got
		} else {
			comps.InplaceIntersect(got)
		}
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(job.call, comps,
		func(p *prog.Prog) bool {
			result := fuzzer.execute(job.exec, &queue.Request{
				Prog:     p,
				ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
				Stat:     fuzzer.statExecHint,
			})
			return !result.Stop()
		})
}
