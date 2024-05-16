// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx    context.Context
	mu     sync.Mutex
	rnd    *rand.Rand
	target *prog.Target

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
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
		Stats:  newStats(),
		Config: cfg,
		Cover:  newCover(),

		ctx:    ctx,
		rnd:    rnd,
		target: target,

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),
	}
	f.execQueues = newExecQueues(f)
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

type execQueues struct {
	smashQueue           *queue.PlainQueue
	triageQueue          *queue.PriorityQueue
	candidateQueue       *queue.PlainQueue
	triageCandidateQueue *queue.PriorityQueue
	source               queue.Source
}

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue: queue.Priority(),
		candidateQueue:       queue.PlainWithStat(fuzzer.StatCandidates),
		triageQueue:          queue.Priority(),
		smashQueue:           queue.Plain(),
	}
	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(
		ret.triageCandidateQueue,
		ret.candidateQueue,
		ret.triageQueue,
		// Alternate smash jobs with exec/fuzz once in 3 times.
		queue.Alternate(ret.smashQueue, 3),
		queue.Callback(fuzzer.genFuzz),
	)
	return ret
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgTypes) *queue.Result {
	executor.Submit(req)
	res := req.Wait(fuzzer.ctx)
	fuzzer.processResult(req, res, flags)
	return res
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgTypes) {
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		fuzzer.processResult(req, res, flags)
		return true
	})
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgTypes) {
	fuzzer.prepare(req, flags)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgTypes) {
	inTriage := flags&progInTriage > 0
	// Triage individual calls.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	// If we are already triaging this exact prog, this is flaky coverage.
	if req.ExecOpts.ExecFlags&ipc.FlagCollectSignal > 0 && res.Info != nil && !inTriage {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, &info, call, flags)
		}
		fuzzer.triageProgCall(req.Prog, &res.Info.Extra, -1, flags)
	}
	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed.Milliseconds()))
	}
}

type Config struct {
	Debug          bool
	Corpus         *corpus.Corpus
	BaseOpts       ipc.ExecOpts // Fuzzer will use BaseOpts as a base for all requests.
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

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *ipc.CallInfo, call int, flags ProgTypes) {
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)

	queue := fuzzer.triageQueue
	if flags&progCandidate > 0 {
		queue = fuzzer.triageCandidateQueue
	}
	fuzzer.startJob(fuzzer.statJobsTriage, &triageJob{
		p:         p.Clone(),
		call:      call,
		info:      *info,
		newSignal: newMaxSignal,
		flags:     flags,
		queue:     queue.AppendQueue(),
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
	fuzzer.prepare(req, 0)
	return req
}

func (fuzzer *Fuzzer) startJob(stat *stats.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		fuzzer.statJobs.Add(1)
		newJob.run(fuzzer)
		fuzzer.statJobs.Add(-1)
		stat.Add(-1)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	req := fuzzer.source.Next()
	if req == nil {
		// The fuzzer is not supposed to issue nil requests.
		panic("nil request from the fuzzer")
	}
	req.ExecOpts = fuzzer.Config.BaseOpts.MergeFlags(req.ExecOpts)
	return req
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

type Candidate struct {
	Prog      *prog.Prog
	Smashed   bool
	Minimized bool
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	for _, candidate := range candidates {
		req, flags := candidateRequest(fuzzer, candidate)
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags)
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	newCt := fuzzer.target.BuildChoiceTable(programs, fuzzer.Config.EnabledCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
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
	return fuzzer.ct
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

func setFlags(execFlags ipc.ExecFlags) ipc.ExecOpts {
	return ipc.ExecOpts{
		ExecFlags: execFlags,
	}
}
