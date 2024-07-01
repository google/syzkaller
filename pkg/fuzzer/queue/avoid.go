// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/stats"
)

type Avoider struct {
	source        Source
	seq           atomic.Uint64
	empty         atomic.Bool
	active        atomic.Pointer[[]atomic.Uint64]
	mu            sync.Mutex
	queue         []*Request
	statDelayed   *stats.Val
	statUndelayed *stats.Val
	statViolated  *stats.Val
}

func Avoid(source Source) *Avoider {
	return &Avoider{
		source: source,
		statDelayed: stats.Create("avoid delayed", "Number of test programs delayed due to VM avoidance",
			stats.Graph("avoid")),
		statUndelayed: stats.Create("avoid undelayed", "Number of test programs undelayed for VM avoidance",
			stats.Graph("avoid")),
		statViolated: stats.Create("avoid violated", "Number of test programs violated VM avoidance",
			stats.Graph("avoid")),
	}
}

// Next returns the next request to execute on the given vm.
// VM = -1 allows to disable delaying logic and drain the queue.
func (avoid *Avoider) Next(vm int) *Request {
	if vm >= 0 {
		avoid.noteActive(vm)
	}
	if req := avoid.delayed(vm); req != nil {
		return req
	}
	for {
		req := avoid.source.Next()
		if req == nil || vm < 0 || !contains(req.Avoid, vm) || !avoid.hasOtherActive(req.Avoid) {
			return req
		}
		avoid.delay(req)
	}
}

func (avoid *Avoider) delay(req *Request) {
	avoid.mu.Lock()
	defer avoid.mu.Unlock()
	req.delayedSince = avoid.seq.Load()
	avoid.queue = append(avoid.queue, req)
	avoid.statDelayed.Add(1)
	avoid.empty.Store(false)
}

func (avoid *Avoider) delayed(vm int) *Request {
	if avoid.empty.Load() {
		return nil
	}
	avoid.mu.Lock()
	defer avoid.mu.Unlock()
	seq := avoid.seq.Load()
	for i, req := range avoid.queue {
		violation := contains(req.Avoid, vm)
		if vm >= 0 && violation && req.delayedSince+1000 > seq {
			continue
		}
		avoid.statUndelayed.Add(1)
		if violation {
			avoid.statViolated.Add(1)
		}
		last := len(avoid.queue) - 1
		avoid.queue[i] = avoid.queue[last]
		avoid.queue[last] = nil
		avoid.queue = avoid.queue[:last]
		avoid.empty.Store(len(avoid.queue) == 0)
		return req
	}
	return nil
}

func (avoid *Avoider) noteActive(vm int) {
	active := avoid.active.Load()
	if active == nil || len(*active) <= vm {
		avoid.mu.Lock()
		active = avoid.active.Load()
		if active == nil || len(*active) <= vm {
			tmp := make([]atomic.Uint64, vm+10)
			active = &tmp
			avoid.active.Store(active)
		}
		avoid.mu.Unlock()
	}
	(*active)[vm].Store(avoid.seq.Add(1))
}

func (avoid *Avoider) hasOtherActive(set []ExecutorID) bool {
	seq := avoid.seq.Load()
	active := *avoid.active.Load()
	for vm := range active {
		if contains(set, vm) {
			continue
		}
		if active[vm].Load()+1000 < seq {
			continue
		}
		return true
	}
	return false
}

func contains(set []ExecutorID, vm int) bool {
	for _, id := range set {
		if id.VM == vm {
			return true
		}
	}
	return false
}
