// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
)

// Work queues hold work items (see Work* struct) and do prioritization among
// them. For example, we want to triage and send to manager new inputs before
// we smash programs in order to not permanently lose interesting programs in
// case of a VM crash.

// GlobalWorkQueue holds work items that are global to the whole syz-fuzzer.
// At the moment these are the work items coming from syz-manager, and we
// naturally want them to be distributed among all procs.
type GlobalWorkQueue struct {
	mu        sync.RWMutex
	candidate []*WorkCandidate

	procs          int
	needCandidates chan struct{}
}

// GroupWorkQueue holds work items for a particular subset of procs. The intent is
// to let the fuzzer operate on different subsystems simultaneously. If only one
// work queue is used for the whole syz-fuzzer, similar progs tend to spread
// over almost all procs. It is not very efficient, e.g. when such progs contain many
// blocking syscalls and, as a result, the whole VM is just idle most of the time.
type GroupWorkQueue struct {
	mu              sync.RWMutex
	globalQueue     *GlobalWorkQueue
	triage          []*WorkTriage
	triageCandidate []*WorkTriage
	smash           []*WorkSmash
}

type ProgTypes int

const (
	ProgCandidate ProgTypes = 1 << iota
	ProgMinimized
	ProgSmashed
	ProgNormal ProgTypes = 0
)

// WorkTriage are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type WorkTriage struct {
	p     *prog.Prog
	call  int
	info  ipc.CallInfo
	flags ProgTypes
}

// WorkCandidate are programs from hub.
// We don't know yet if they are useful for this fuzzer or not.
// A proc handles them the same way as locally generated/mutated programs.
type WorkCandidate struct {
	p     *prog.Prog
	flags ProgTypes
}

// WorkSmash are programs just added to corpus.
// During smashing these programs receive a one-time special attention
// (emit faults, collect comparison hints, etc).
type WorkSmash struct {
	p    *prog.Prog
	call int
}

func newGlobalWorkQueue(procs int, needCandidates chan struct{}) *GlobalWorkQueue {
	return &GlobalWorkQueue{
		procs:          procs,
		needCandidates: needCandidates,
	}
}

func (wq *GlobalWorkQueue) enqueue(item interface{}) {
	wq.mu.Lock()
	defer wq.mu.Unlock()
	switch item := item.(type) {
	case *WorkCandidate:
		wq.candidate = append(wq.candidate, item)
	default:
		panic("GlobalWorkQueue: unknown work type")
	}
}

func (wq *GlobalWorkQueue) dequeue() (item interface{}) {
	wq.mu.Lock()
	wantCandidates := false
	if len(wq.candidate) != 0 {
		last := len(wq.candidate) - 1
		item = wq.candidate[last]
		wq.candidate = wq.candidate[:last]
		wantCandidates = len(wq.candidate) < wq.procs
	}
	wq.mu.Unlock()
	if wantCandidates {
		select {
		case wq.needCandidates <- struct{}{}:
		default:
		}
	}
	return item
}

func (wq *GlobalWorkQueue) wantCandidates() bool {
	wq.mu.RLock()
	defer wq.mu.RUnlock()
	return len(wq.candidate) < wq.procs
}

func newGroupWorkQueue(global *GlobalWorkQueue) *GroupWorkQueue {
	return &GroupWorkQueue{
		globalQueue: global,
	}
}

func (wq *GroupWorkQueue) enqueue(item interface{}) {
	wq.mu.Lock()
	defer wq.mu.Unlock()
	switch item := item.(type) {
	case *WorkTriage:
		if item.flags&ProgCandidate != 0 {
			wq.triageCandidate = append(wq.triageCandidate, item)
		} else {
			wq.triage = append(wq.triage, item)
		}
	case *WorkSmash:
		wq.smash = append(wq.smash, item)
	default:
		panic("GroupWorkQueue: unknown work type")
	}
}

func (wq *GroupWorkQueue) dequeue() (item interface{}) {
	// Triage candidate have the highest priority - handle them first.
	wq.mu.Lock()
	if len(wq.triageCandidate) != 0 {
		last := len(wq.triageCandidate) - 1
		item = wq.triageCandidate[last]
		wq.triageCandidate = wq.triageCandidate[:last]
	}
	wq.mu.Unlock()
	if item != nil {
		return
	}

	// If there are no triage candidates, ry to query the global queue
	// for a candidate.
	item = wq.globalQueue.dequeue()
	if item != nil {
		return
	}
	wq.mu.Lock()
	if len(wq.triage) != 0 {
		last := len(wq.triage) - 1
		item = wq.triage[last]
		wq.triage = wq.triage[:last]
	} else if len(wq.smash) != 0 {
		last := len(wq.smash) - 1
		item = wq.smash[last]
		wq.smash = wq.smash[:last]
	}
	wq.mu.Unlock()
	return item
}
