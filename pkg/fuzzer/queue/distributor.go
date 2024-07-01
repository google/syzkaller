// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/stat"
)

// Distributor distributes requests to different VMs during input triage
// (allows to avoid already used VMs).
type Distributor struct {
	source        Source
	seq           atomic.Uint64
	empty         atomic.Bool
	active        atomic.Pointer[[]atomic.Uint64]
	mu            sync.Mutex
	queue         []*Request
	statDelayed   *stat.Val
	statUndelayed *stat.Val
	statViolated  *stat.Val
}

func Distribute(source Source) *Distributor {
	return &Distributor{
		source: source,
		statDelayed: stat.New("distributor delayed", "Number of test programs delayed due to VM avoidance",
			stat.Graph("distributor")),
		statUndelayed: stat.New("distributor undelayed", "Number of test programs undelayed for VM avoidance",
			stat.Graph("distributor")),
		statViolated: stat.New("distributor violated", "Number of test programs violated VM avoidance",
			stat.Graph("distributor")),
	}
}

// Next returns the next request to execute on the given vm.
func (dist *Distributor) Next(vm int) *Request {
	dist.noteActive(vm)
	if req := dist.delayed(vm); req != nil {
		return req
	}
	for {
		req := dist.source.Next()
		if req == nil || !contains(req.Avoid, vm) || !dist.hasOtherActive(req.Avoid) {
			return req
		}
		dist.delay(req)
	}
}

func (dist *Distributor) delay(req *Request) {
	dist.mu.Lock()
	defer dist.mu.Unlock()
	req.delayedSince = dist.seq.Load()
	dist.queue = append(dist.queue, req)
	dist.statDelayed.Add(1)
	dist.empty.Store(false)
}

func (dist *Distributor) delayed(vm int) *Request {
	if dist.empty.Load() {
		return nil
	}
	dist.mu.Lock()
	defer dist.mu.Unlock()
	seq := dist.seq.Load()
	for i, req := range dist.queue {
		violation := contains(req.Avoid, vm)
		// The delayedSince check protects from a situation when we had another VM available,
		// and delayed a request, but then the VM was taken for reproduction and does not
		// serve requests any more. If we could not dispatch a request in 1000 attempts,
		// we gave up and give it to any VM.
		if violation && req.delayedSince+1000 > seq {
			continue
		}
		dist.statUndelayed.Add(1)
		if violation {
			dist.statViolated.Add(1)
		}
		last := len(dist.queue) - 1
		dist.queue[i] = dist.queue[last]
		dist.queue[last] = nil
		dist.queue = dist.queue[:last]
		dist.empty.Store(len(dist.queue) == 0)
		return req
	}
	return nil
}

func (dist *Distributor) noteActive(vm int) {
	active := dist.active.Load()
	if active == nil || len(*active) <= vm {
		dist.mu.Lock()
		active = dist.active.Load()
		if active == nil || len(*active) <= vm {
			tmp := make([]atomic.Uint64, vm+10)
			active = &tmp
			dist.active.Store(active)
		}
		dist.mu.Unlock()
	}
	(*active)[vm].Store(dist.seq.Add(1))
}

// hasOtherActive says if we recently seen activity from VMs not in the set.
func (dist *Distributor) hasOtherActive(set []ExecutorID) bool {
	seq := dist.seq.Load()
	active := *dist.active.Load()
	for vm := range active {
		if contains(set, vm) {
			continue
		}
		// 1000 is semi-random notion of recency.
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
