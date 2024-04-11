// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import "github.com/google/syzkaller/pkg/stats"

// Retryer gives a second chance to the inputs from crashed VMs.
type Retryer struct {
	fuzzer           FuzzerOps
	delayed          *priorityQueue[*Request]
	statRiskyRetries *stats.Val
}

func NewRetryer(base FuzzerOps) *Retryer {
	ret := &Retryer{
		fuzzer:  base,
		delayed: makePriorityQueue[*Request](),
		statRiskyRetries: stats.Create("risky prog reruns", "Reexecuted inputs from crashed VMs",
			stats.Rate{}, stats.StackedGraph("prog reruns")),
	}
	stats.Create("risky prog queue", "Queued inputs from crashed VMs",
		func() int {
			return ret.delayed.Len()
		}, stats.StackedGraph("prog reruns"))
	return ret
}

func (retryer *Retryer) NextInput(opts RequestOpts) *Request {
	if opts.MayRisk {
		item := retryer.delayed.tryPop()
		if item != nil {
			item.value.retried = true
			retryer.statRiskyRetries.Add(1)
			return item.value
		}
	}
	return retryer.fuzzer.NextInput(opts)
}

// No sense to let the queue grow infinitely.
// If we're going above the limit, something is seriously wrong with the DUT.
const retryerQueueLimit = 10000

func (retryer *Retryer) Done(req *Request, res *Result) {
	if !res.Crashed || req.noRetry || req.retried ||
		retryer.delayed.Len() > retryerQueueLimit {
		retryer.fuzzer.Done(req, res)
		return
	}
	// Let's push without using priorities for now.
	retryer.delayed.push(&priorityQueueItem[*Request]{
		value: req,
	})
}
