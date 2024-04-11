// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

// FuzzerOps is what actual request executors need from the fuzzer.
type FuzzerOps interface {
	NextInput(RequestOpts) *Request
	Done(req *Request, res *Result)
	SetUnsafeSyscalls(map[*prog.Syscall]struct{})
}

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx    context.Context
	mu     sync.Mutex
	rnd    *rand.Rand
	target *prog.Target

	ctSafe       *prog.ChoiceTable
	ctUnsafe     *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
	ctRegenerate chan struct{}

	nextExec    *priorityQueue[*Request]
	nextJobID   atomic.Int64
	unsafeCalls atomic.Value // map[*prog.Syscall]struct{}
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	f := &Fuzzer{
		Stats:  newStats(),
		Config: cfg,
		Cover:  newCover(),

		ctx:    ctx,
		rnd:    rnd,
		target: target,

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),

		nextExec: makePriorityQueue[*Request](),
	}
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

type Config struct {
	Debug          bool
	Corpus         *corpus.Corpus
	Logf           func(level int, msg string, args ...interface{})
	Coverage       bool
	FaultInjection bool
	Comparisons    bool
	Collide        bool
	EnabledCalls   map[*prog.Syscall]bool
	NoMutateCalls  map[int]bool
	FetchRawCover  bool
	NewInputFilter func(call string) bool
}

type Request struct {
	Prog         *prog.Prog
	NeedCover    bool
	NeedRawCover bool
	NeedSignal   rpctype.SignalType
	NeedHints    bool
	SignalFilter signal.Signal // If specified, the resulting signal MAY be a subset of it.
	// Fields that are only relevant within pkg/fuzzer.
	flags   ProgTypes
	stat    *stats.Val
	resultC chan *Result

	preserveProg bool // never modify the Prog
	retried      bool // whether the request has already been resent
	prio         priority
}

type Result struct {
	Info    *ipc.ProgInfo
	Crashed bool
}

func (fuzzer *Fuzzer) Done(req *Request, res *Result) {
	// Triage individual calls.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	if req.NeedSignal != rpctype.NoSignal && res.Info != nil {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, &info, call, req.flags)
		}
		fuzzer.triageProgCall(req.Prog, &res.Info.Extra, -1, req.flags)
	}
	// Unblock threads that wait for the result.
	if req.resultC != nil {
		req.resultC <- res
	}
	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed.Milliseconds()))
	}
	req.stat.Add(1)
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *ipc.CallInfo, call int,
	flags ProgTypes) {
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if flags&progInTriage > 0 {
		// We are already triaging this exact prog.
		// All newly found coverage is flaky.
		fuzzer.Logf(2, "found new flaky signal in call %d in %s", call, p)
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	fuzzer.startJob(fuzzer.statJobsTriage, &triageJob{
		p:           p.Clone(),
		call:        call,
		info:        *info,
		newSignal:   newMaxSignal,
		flags:       flags,
		jobPriority: triageJobPrio(flags),
	})
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

type Candidate struct {
	Prog      *prog.Prog
	Smashed   bool
	Minimized bool
}

type RequestOpts struct {
	MayRisk bool // whether we may run inputs that are likely to crash the VM.
}

func (fuzzer *Fuzzer) NextInput(opts RequestOpts) *Request {
	req := fuzzer.nextInput(opts.MayRisk)
	if req.stat == fuzzer.statExecCandidate {
		fuzzer.StatCandidates.Add(-1)
	}
	return req
}

func (fuzzer *Fuzzer) nextInput(risky bool) *Request {
	nextExec := fuzzer.nextExec.pop()

	// The fuzzer may become too interested in potentially very long hint and smash jobs.
	// Let's leave more space for new input space exploration.
	if nextExec != nil {
		if nextExec.prio.greaterThan(priority{smashPrio}) || fuzzer.nextRand()%3 != 0 {
			return nextExec.value
		} else {
			fuzzer.nextExec.push(nextExec)
		}
	}

	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	rnd := fuzzer.rand()
	if rnd.Float64() < mutateRate {
		req := mutateProgRequest(fuzzer, rnd, risky)
		if req != nil {
			return req
		}
	}
	return genProgRequest(fuzzer, rnd, risky)
}

func (fuzzer *Fuzzer) startJob(stat *stats.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	if impl, ok := newJob.(jobSaveID); ok {
		// E.g. for big and slow hint jobs, we would prefer not to serialize them,
		// but rather to start them all in parallel.
		impl.saveID(-fuzzer.nextJobID.Add(1))
	}
	go func() {
		stat.Add(1)
		fuzzer.statJobs.Add(1)
		newJob.run(fuzzer)
		fuzzer.statJobs.Add(-1)
		stat.Add(-1)
	}()
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.StatCandidates.Add(len(candidates))
	for _, candidate := range candidates {
		fuzzer.pushExec(candidateRequest(fuzzer, candidate), priority{candidatePrio})
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	return rand.New(rand.NewSource(fuzzer.nextRand()))
}

func (fuzzer *Fuzzer) nextRand() int64 {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return fuzzer.rnd.Int63()
}

func (fuzzer *Fuzzer) pushExec(req *Request, prio priority) {
	if req.NeedHints && (req.NeedCover || req.NeedSignal != rpctype.NoSignal) {
		panic("Request.NeedHints is mutually exclusive with other fields")
	}
	fuzzer.nextExec.push(&priorityQueueItem[*Request]{
		value: req, prio: prio,
	})
}

func (fuzzer *Fuzzer) exec(job job, req *Request) *Result {
	req.resultC = make(chan *Result, 1)
	prio := job.priority()
	req.prio = prio
	fuzzer.pushExec(req, prio)
	select {
	case <-fuzzer.ctx.Done():
		// Pretend the input has crashed to stop corresponding jobs.
		return &Result{Crashed: true}
	case res := <-req.resultC:
		close(req.resultC)
		return res
	}
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	enabledCalls := fuzzer.Config.EnabledCalls
	newCtUnsafe := fuzzer.target.BuildChoiceTable(programs, enabledCalls)
	newCtSafe := newCtUnsafe

	if calls, ok := fuzzer.unsafeCalls.Load().(map[*prog.Syscall]struct{}); ok && len(calls) > 0 {
		for call := range calls {
			enabledCalls[call] = false
		}
		newCtSafe = fuzzer.target.BuildChoiceTable(programs, enabledCalls)
	}

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ctSafe = newCtSafe
		fuzzer.ctUnsafe = newCtUnsafe
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.Programs())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	return fuzzer.getChoiceTable(false)
}

func (fuzzer *Fuzzer) getChoiceTable(risky bool) *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.Programs()

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	if risky {
		return fuzzer.ctUnsafe
	}
	return fuzzer.ctSafe
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

		str := fmt.Sprintf("exec queue size: %d, running jobs: %d, heap (MB): %d",
			fuzzer.nextExec.Len(), fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func (fuzzer *Fuzzer) RotateMaxSignal(items int) {
	corpusSignal := fuzzer.Config.Corpus.Signal()
	pureMaxSignal := fuzzer.Cover.pureMaxSignal(corpusSignal)
	if pureMaxSignal.Len() < items {
		items = pureMaxSignal.Len()
	}
	fuzzer.Logf(1, "rotate %d max signal elements", items)

	delta := pureMaxSignal.RandomSubset(fuzzer.rand(), items)
	fuzzer.Cover.subtract(delta)
}

func (fuzzer *Fuzzer) SetUnsafeSyscalls(syscalls map[*prog.Syscall]struct{}) {
	fuzzer.unsafeCalls.Store(syscalls)
	fuzzer.ctRegenerate <- struct{}{}
}
