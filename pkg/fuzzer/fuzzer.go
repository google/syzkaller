// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzzer orchestrates syzkaller fuzzing logic, corpus distribution, and signal updates.
package fuzzer

import (
	"cmp"
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"slices"
	"sync"
	"time"

	pkgfeatures "github.com/google/syzkaller/pkg/vminfo/features"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx          context.Context
	mu           sync.Mutex
	rnd          *rand.Rand
	target       *prog.Target
	hintsLimiter prog.HintsLimiter
	runningJobs  map[jobIntrospector]struct{}

	ct           *prog.ChoiceTable
	ctProgs      int
	ctAllProgs   int
	ctRelated    []*prog.Prog
	ctMu         sync.RWMutex
	ctRegenerate chan struct{}

	execQueues
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	f := &Fuzzer{
		Stats:  newStats(target),
		Config: cfg,
		Cover:  newCover(),

		ctx:         ctx,
		rnd:         rnd,
		target:      target,
		runningJobs: map[jobIntrospector]struct{}{},

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),
	}
	f.execQueues = newExecQueues(f)
	f.updateChoiceTable()
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

func (fuzzer *Fuzzer) RecommendedCalls() int {
	if fuzzer.Config.ModeKFuzzTest {
		return prog.RecommendedCallsKFuzzTest
	}
	return prog.RecommendedCalls
}

type execQueues struct {
	triageCandidateQueue *queue.DynamicOrderer
	candidateQueue       *queue.PlainQueue
	tiers                []focusTier
	source               queue.Source
}

type focusTier struct {
	coverPCs    map[uint64]struct{}
	weight      float64
	inFocus     bool
	triageQueue *queue.DynamicOrderer
	smashQueue  *queue.PlainQueue
	hintsQueue  *queue.PlainQueue
}

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue: queue.DynamicOrder(),
		candidateQueue:       queue.Plain(),
	}
	catchAllWeight := 1.0
	if fuzzer.Config.PatchTest && fuzzer.Config.Corpus != nil {
		areas := fuzzer.Config.Corpus.FocusAreas()
		slices.SortStableFunc(areas, func(a, b corpus.FocusArea) int {
			return cmp.Compare(b.Weight, a.Weight)
		})
		for _, area := range areas {
			if area.Weight <= 0 {
				continue
			}
			if len(area.CoverPCs) == 0 {
				catchAllWeight = area.Weight
				continue
			}
			ret.tiers = append(ret.tiers, focusTier{
				coverPCs:    area.CoverPCs,
				weight:      area.Weight,
				inFocus:     true,
				triageQueue: queue.DynamicOrder(),
				smashQueue:  queue.Plain(),
				hintsQueue:  queue.Plain(),
			})
		}
	}
	// Always append a catch-all tier at the end.
	ret.tiers = append(ret.tiers, focusTier{
		weight:      catchAllWeight,
		inFocus:     !fuzzer.Config.PatchTest || len(ret.tiers) == 0,
		triageQueue: queue.DynamicOrder(),
		smashQueue:  queue.Plain(),
		hintsQueue:  queue.Plain(),
	})

	// Alternate smash/hints jobs with exec/fuzz to spread attention to the wider area.
	fuzzShare := 0.5
	if fuzzer.Config.PatchTest {
		// When we do patch fuzzing, we do not focus on finding and persisting
		// new coverage that much, so it's reasonable to spend more time just
		// mutating various corpus programs.
		fuzzShare = 1.0
	}
	var weighted []queue.WeightedSource
	var totalWeight float64
	for _, tier := range ret.tiers {
		weighted = append(weighted,
			queue.WeightedSource{
				Source: tier.smashQueue,
				Weight: tier.weight * 0.7,
			},
			queue.WeightedSource{
				Source: tier.hintsQueue,
				Weight: tier.weight * 0.3,
			},
		)
		totalWeight += tier.weight
	}
	weighted = append(weighted, queue.WeightedSource{
		Source: queue.Callback(fuzzer.genFuzz),
		Weight: totalWeight * fuzzShare,
	})

	sources := []queue.Source{
		ret.triageCandidateQueue,
		ret.candidateQueue,
	}
	for _, tier := range ret.tiers {
		sources = append(sources, tier.triageQueue)
	}
	sources = append(sources, queue.Weighted(fuzzer.rand(), weighted...))
	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(sources...)
	return ret
}

func (fuzzer *Fuzzer) triageQueueForCalls(triage map[int]*triageCall) *queue.DynamicOrderer {
	for _, tier := range fuzzer.tiers[:len(fuzzer.tiers)-1] {
		for _, call := range triage {
			if call.newSignal.HasAny(tier.coverPCs) {
				return tier.triageQueue
			}
		}
	}
	return fuzzer.tiers[len(fuzzer.tiers)-1].triageQueue
}

func (fuzzer *Fuzzer) tierForCall(info *triageCall) *focusTier {
	for i := range len(fuzzer.tiers) - 1 {
		tier := &fuzzer.tiers[i]
		if info.newStableSignal.HasAny(tier.coverPCs) {
			return tier
		}
	}
	for i := range len(fuzzer.tiers) - 1 {
		tier := &fuzzer.tiers[i]
		for pc := range info.cover {
			if _, ok := tier.coverPCs[pc]; ok {
				return tier
			}
		}
	}
	return &fuzzer.tiers[len(fuzzer.tiers)-1]
}

func (fuzzer *Fuzzer) CandidatesToTriage() int {
	return fuzzer.statCandidates.Val() + fuzzer.statJobsTriageCandidate.Val()
}

func (fuzzer *Fuzzer) CandidateTriageFinished() bool {
	return fuzzer.CandidatesToTriage() == 0
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgFlags) *queue.Result {
	fuzzer.enqueue(executor, req, flags, 0)
	return req.Wait(fuzzer.ctx)
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgFlags, attempt int) {
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	// If we are already triaging this exact prog, this is flaky coverage.
	// Hanged programs are harmful as they consume executor procs.
	dontTriage := flags&progInTriage > 0 || res.Status == queue.Hanged
	// Triage the program.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	var triage map[int]*triageCall
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 && res.Info != nil && !dontTriage {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, info, call, &triage)
		}
		fuzzer.triageProgCall(req.Prog, res.Info.Extra, -1, &triage)

		if len(triage) != 0 {
			queue, stat := fuzzer.triageQueueForCalls(triage), fuzzer.statJobsTriage
			jobType := JobTriage
			if flags&progCandidate > 0 {
				queue, stat = fuzzer.triageCandidateQueue, fuzzer.statJobsTriageCandidate
				jobType = JobCandidateTriage
			}
			job := &triageJob{
				p:        req.Prog.Clone(),
				executor: res.Executor,
				flags:    flags,
				queue:    queue.Append(),
				calls:    triage,
				info: &JobInfo{
					Name: req.Prog.String(),
					Type: jobType,
				},
			}
			for id := range triage {
				job.info.Calls = append(job.info.Calls, job.p.CallName(id))
			}
			slices.Sort(job.info.Calls)
			fuzzer.startJob(stat, job)
		}
	}

	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed / 1e6))
		for call, info := range res.Info.Calls {
			fuzzer.handleCallInfo(req, info, call)
		}
		fuzzer.handleCallInfo(req, res.Info.Extra, -1)
	}

	// Corpus candidates may have flaky coverage, so we give them up to 3 retries
	// (or just 1 in PatchTest mode to avoid spending too much time on corpus retriage).
	maxCandidateAttempts := 3
	if fuzzer.Config.PatchTest {
		maxCandidateAttempts = 1
	}
	if req.Risky() {
		// In non-snapshot mode usually we are not sure which exactly input caused the crash,
		// so give it one more chance. In snapshot mode we know for sure, so don't retry.
		maxCandidateAttempts = min(maxCandidateAttempts, 2)
		if fuzzer.Config.Snapshot || res.Status == queue.Hanged {
			maxCandidateAttempts = 0
		}
	}
	if len(triage) == 0 && flags&ProgFromCorpus != 0 && attempt < maxCandidateAttempts {
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags, attempt+1)
		return false
	}
	if flags&progCandidate != 0 {
		fuzzer.statCandidates.Add(-1)
	}
	return true
}

type Config struct {
	Debug          bool
	Corpus         *corpus.Corpus
	Logf           func(level int, msg string, args ...any)
	Snapshot       bool
	Coverage       bool
	FaultInjection bool
	Comparisons    bool
	Collide        bool
	EnabledCalls   map[*prog.Syscall]bool
	NoMutateCalls  map[int]bool
	FetchRawCover  bool
	NewInputFilter func(call string) bool
	PatchTest      bool
	ModeKFuzzTest  bool
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *flatrpc.CallInfo, call int, triage *map[int]*triageCall) {
	if info == nil {
		return
	}
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	if *triage == nil {
		*triage = make(map[int]*triageCall)
	}
	(*triage)[call] = &triageCall{
		errno:     info.Error,
		newSignal: newMaxSignal,
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw(info.Signal, prio)},
	}
}

func (fuzzer *Fuzzer) handleCallInfo(req *queue.Request, info *flatrpc.CallInfo, call int) {
	if info == nil || info.Flags&flatrpc.CallFlagCoverageOverflow == 0 {
		return
	}
	syscallIdx := len(fuzzer.Syscalls) - 1
	if call != -1 {
		syscallIdx = req.Prog.Calls[call].Meta.ID
	}
	stat := &fuzzer.Syscalls[syscallIdx]
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		stat.CompsOverflows.Add(1)
		fuzzer.statCompsOverflows.Add(1)
	} else {
		stat.CoverOverflows.Add(1)
		fuzzer.statCoverOverflows.Add(1)
	}
}

func signalPrio(p *prog.Prog, info *flatrpc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Error == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func (fuzzer *Fuzzer) genFuzz() *queue.Request {
	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	var req *queue.Request
	rnd := fuzzer.rand()
	if rnd.Float64() < mutateRate {
		req = mutateProgRequest(fuzzer, rnd)
	}
	if req == nil {
		req = genProgRequest(fuzzer, rnd)
	}
	if fuzzer.Config.Collide && rnd.Intn(3) == 0 {
		req = &queue.Request{
			Prog: randomCollide(req.Prog, rnd),
			Stat: fuzzer.statExecCollide,
		}
	}
	fuzzer.prepare(req, 0, 0)
	return req
}

func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		defer stat.Add(-1)

		fuzzer.statJobs.Add(1)
		defer fuzzer.statJobs.Add(-1)

		if obj, ok := newJob.(jobIntrospector); ok {
			fuzzer.mu.Lock()
			fuzzer.runningJobs[obj] = struct{}{}
			fuzzer.mu.Unlock()

			defer func() {
				fuzzer.mu.Lock()
				delete(fuzzer.runningJobs, obj)
				fuzzer.mu.Unlock()
			}()
		}

		newJob.run(fuzzer)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	req := fuzzer.source.Next()
	if req == nil {
		// The fuzzer is not supposed to issue nil requests.
		panic("nil request from the fuzzer")
	}
	return req
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...any) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

type ProgFlags int

const (
	// The candidate was loaded from our local corpus rather than come from hub.
	ProgFromCorpus ProgFlags = 1 << iota
	ProgMinimized
	ProgSmashed

	progCandidate
	progInTriage
)

type Candidate struct {
	Prog  *prog.Prog
	Flags ProgFlags
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.statCandidates.Add(len(candidates))
	for _, candidate := range candidates {
		req := &queue.Request{
			Prog:      candidate.Prog,
			ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:      fuzzer.statExecCandidate,
			Important: true,
		}
		fuzzer.enqueue(fuzzer.candidateQueue, req, candidate.Flags|progCandidate, 0)
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable() {
	var progs, focused, all []*prog.Prog
	if fuzzer.Config.Corpus != nil {
		focused = fuzzer.Config.Corpus.FocusedPrograms()
		all = fuzzer.Config.Corpus.Programs()
	}
	progs = all
	var related []*prog.Prog
	if len(focused) > 0 {
		fuzzer.ctMu.RLock()
		baseCt := fuzzer.ct
		fuzzer.ctMu.RUnlock()
		if baseCt == nil {
			baseCt = fuzzer.target.BuildChoiceTable(nil, fuzzer.Config.EnabledCalls)
		}
		related = baseCt.RelatedPrograms(focused, all)
		progs = related
	}
	newCt := fuzzer.target.BuildChoiceTable(progs, fuzzer.Config.EnabledCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	fuzzer.ctProgs = len(focused)
	if len(focused) == 0 {
		fuzzer.ctProgs = len(all)
	}
	fuzzer.ctAllProgs = len(all)
	fuzzer.ctRelated = related
	fuzzer.ct = newCt
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable()
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	var focusedLen, allLen int
	if fuzzer.Config.Corpus != nil {
		focusedLen = len(fuzzer.Config.Corpus.FocusedPrograms())
		allLen = len(fuzzer.Config.Corpus.Programs())
	}
	progsLen := allLen
	if focusedLen > 0 {
		progsLen = focusedLen
	}

	fuzzer.ctMu.RLock()
	defer fuzzer.ctMu.RUnlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if fuzzer.Config.PatchTest {
		regenerateEveryProgs = max(1, progsLen/10)
	} else if progsLen < 100 {
		regenerateEveryProgs = 33
	}
	needRegen := progsLen < fuzzer.ctProgs || fuzzer.ctProgs+regenerateEveryProgs <= progsLen
	if focusedLen > 0 {
		allStep := max(333, allLen/5)
		needRegen = needRegen || allLen < fuzzer.ctAllProgs || fuzzer.ctAllProgs+allStep <= allLen
	}
	if needRegen {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) relatedPrograms() []*prog.Prog {
	fuzzer.ctMu.RLock()
	defer fuzzer.ctMu.RUnlock()
	return fuzzer.ctRelated
}

func (fuzzer *Fuzzer) RunningJobs() []*JobInfo {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()

	var ret []*JobInfo
	for item := range fuzzer.runningJobs {
		ret = append(ret, item.getInfo())
	}
	return ret
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("running jobs: %d, heap (MB): %d",
			fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func setFlags(execFlags flatrpc.ExecFlag) flatrpc.ExecOpts {
	return flatrpc.ExecOpts{
		ExecFlags: execFlags,
	}
}

// DefaultExecOpts returns default execution options.
// TODO: This method belongs better to pkg/flatrpc, but we currently end up
// having a cyclic dependency error.
func DefaultExecOpts(cfg *mgrconfig.Config, features flatrpc.Feature, debug bool) flatrpc.ExecOpts {
	env := pkgfeatures.FeaturesToFlags(features, nil)
	if debug {
		env |= flatrpc.ExecEnvDebug
	}
	if cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: cfg.SandboxArg,
	}
}
