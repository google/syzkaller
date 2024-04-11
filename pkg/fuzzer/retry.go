// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

// Retryer gives a second chance to the inputs from crashed VMs.
type Retryer struct {
	fuzzer           FuzzerOps
	delayedFromCrash *priorityQueue[*Request]
	delayedRisky     *priorityQueue[*Request]

	statRiskyRetries   *stats.Val
	statRiskyDiscarded *stats.Val
	statRiskyRun       *stats.Val

	mu             sync.Mutex
	rnd            *rand.Rand
	dangerousCalls map[*prog.Syscall]struct{}

	crashEstimator
}

func NewRetryer(base FuzzerOps) *Retryer {
	ret := &Retryer{
		fuzzer:           base,
		delayedFromCrash: makePriorityQueue[*Request](),
		delayedRisky:     makePriorityQueue[*Request](),

		statRiskyRetries: stats.Create("risky prog reruns", "Reexecuted risky progs",
			stats.Rate{}, stats.StackedGraph("prog reruns")),
		statRiskyDiscarded: stats.Create("risky progs discarded", "Inputs deemeed too risky for execution",
			stats.Rate{}, stats.StackedGraph("risky progs")),
		statRiskyRun: stats.Create("risky progs run", "New risky progs",
			stats.Rate{}, stats.StackedGraph("risky progs")),
		rnd: rand.New(rand.NewSource(0)),
	}
	stats.Create("risky prog queue", "Queued risky inputs",
		func() int {
			return ret.delayedRisky.Len()
		}, stats.StackedGraph("prog reruns"))
	stats.Create("crashed prog queue", "Queued inputs from crashed VMs",
		func() int {
			return ret.delayedFromCrash.Len()
		}, stats.StackedGraph("prog reruns"))

	stats.Create("risky syscalls", "Risky syscall count",
		func() int {
			ret.mu.Lock()
			defer ret.mu.Unlock()
			return len(ret.dangerousCalls)
		}, stats.StackedGraph("risky syscalls"))

	go func() {
		i := 0
		for range time.NewTicker(time.Minute / 2).C {
			disabled := ret.getDangerousCalls(0.025, 750)
			if i%2 == 0 {
				base.SetUnsafeSyscalls(disabled)
				ret.printCallEstimates()
			}
			i++

			ret.mu.Lock()
			ret.dangerousCalls = disabled
			ret.mu.Unlock()
		}
	}()
	return ret
}

func (retryer *Retryer) nextRand() float64 {
	retryer.mu.Lock()
	defer retryer.mu.Unlock()
	return retryer.rnd.Float64()
}

func (retryer *Retryer) NextInput(opts RequestOpts) *Request {
	if opts.MayRisk {
		var item *priorityQueueItem[*Request]
		if retryer.nextRand() < 0.05 {
			// Once in 20 times, pick an item from the queue of crashed inputs.
			item = retryer.delayedFromCrash.tryPop()
			if item != nil {
				item.value.retried = true
			}
		}
		if item == nil {
			// If there are no inputs from crashed VMs, look at the delayed ones.
			// Note that we don't set retried=true since we have never executed the input yet.
			item = retryer.delayedRisky.tryPop()
		}
		if item != nil {
			retryer.statRiskyRetries.Add(1)
			return item.value
		}
	}

	for attempts := 0; ; attempts++ {
		input := retryer.fuzzer.NextInput(opts)
		dangerous := retryer.isDangerous(input.Prog)
		if !dangerous || opts.MayRisk {
			if dangerous {
				retryer.statRiskyRun.Add(1)
			}
			return input
		}
		if input.preserveProg {
			// The input must be preserved - delay it until there comes a MayRisk=true VM.
			retryer.toBacklog(input, false)
		} else {
			// Just ignore the input.
			retryer.statRiskyDiscarded.Add(1)
			retryer.fuzzer.Done(input, &Result{Crashed: true})
		}
	}
}

func (retryer *Retryer) isDangerous(p *prog.Prog) bool {
	retryer.mu.Lock()
	defer retryer.mu.Unlock()
	for _, call := range p.Calls {
		if _, ok := retryer.dangerousCalls[call.Meta]; ok {
			return true
		}
	}
	return false
}

func (retryer *Retryer) SetUnsafeSyscalls(syscalls map[*prog.Syscall]struct{}) {
	panic("not implemented")
}

// No sense to let the queue grow infinitely.
// If we're going above the limit, something is seriously wrong with the DUT.
const retryerQueueLimit = 10000

func (retryer *Retryer) Done(req *Request, res *Result) {
	if res.Crashed {
		retryer.Avoid(req.Prog)
		retryer.toBacklog(req, true)
	} else {
		retryer.OK(req.Prog)
		retryer.fuzzer.Done(req, res)
	}
}

func (retryer *Retryer) toBacklog(req *Request, fromCrash bool) {
	queue := retryer.delayedRisky
	if fromCrash {
		queue = retryer.delayedFromCrash
	}
	if !req.preserveProg || req.retried || queue.Len() > retryerQueueLimit {
		retryer.fuzzer.Done(req, &Result{Crashed: true})
		return
	}
	queue.push(&priorityQueueItem[*Request]{
		value: req, prio: req.prio,
	})
}

type crashEstimator struct {
	mu        sync.RWMutex
	callProbs map[*prog.Syscall]*stats.AverageValue[float64]
}

func (ce *crashEstimator) OK(p *prog.Prog) {
	// We are okay to miss some good executions.
	ce.save(p, 0, false)
}

func (ce *crashEstimator) Avoid(p *prog.Prog) {
	// But all bad executions must be recorded.
	ce.save(p, 1.0, false)
}

func (ce *crashEstimator) CrashProbability(p *prog.Prog) float64 {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	prob := 0.0
	for _, call := range p.Calls {
		estimate := ce.callProbs[call.Meta]
		if estimate == nil || estimate.Count() < 3 {
			continue
		}
		value := estimate.Value()
		if value > prob {
			prob = value
		}
	}
	return prob
}

func (ce *crashEstimator) save(p *prog.Prog, prob float64, tentative bool) {
	if !ce.mu.TryLock() {
		if tentative {
			return
		}
		ce.mu.Lock()
	}
	defer ce.mu.Unlock()

	if ce.callProbs == nil {
		ce.callProbs = map[*prog.Syscall]*stats.AverageValue[float64]{}
	}
	for _, call := range p.Calls {
		estimate := ce.callProbs[call.Meta]
		if estimate == nil {
			estimate = &stats.AverageValue[float64]{}
			ce.callProbs[call.Meta] = estimate
		}
		estimate.Save(prob)
	}
}

func (ce *crashEstimator) getDangerousCalls(cutOff float64, max int) map[*prog.Syscall]struct{} {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	items := ce.sortedProbabilities()
	if max > len(items)/4 {
		max = len(items) / 4
	}

	ret := map[*prog.Syscall]struct{}{}
	for _, item := range items {
		if item.prob < cutOff || len(ret) == max {
			break
		}
		ret[item.call] = struct{}{}
	}
	return ret
}

type syscallProb struct {
	call *prog.Syscall
	prob float64
}

func (ce *crashEstimator) sortedProbabilities() []syscallProb {
	ce.mu.RLock()
	var items []syscallProb
	for key, v := range ce.callProbs {
		items = append(items, syscallProb{key, v.Value()})
	}
	ce.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].prob > items[j].prob })
	return items
}

// Needed for debugging.
func (ce *crashEstimator) printCallEstimates() {
	items := ce.sortedProbabilities()
	const limit = 50
	if len(items) > limit {
		items = items[:limit]
	}
	for _, info := range items {
		log.Logf(0, "call %s: prob %.3f", info.call.Name, info.prob)
	}
}
