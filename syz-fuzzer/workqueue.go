// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
)

// WorkQueue holds global non-fuzzing work items (see the Work* structs below).
// WorkQueue also does prioritization among work items, for example, we want
// to triage and send to manager new inputs before we smash programs
// in order to not permanently lose interesting programs in case of VM crash.
type WorkQueue struct {
	mu              sync.RWMutex
	triageCandidate []*WorkTriage
	candidate       []*WorkCandidate
	triage          []*WorkTriage
	smash           []*WorkSmash

	procs          int
	needCandidates chan struct{}
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

func newWorkQueue(procs int, needCandidates chan struct{}) *WorkQueue {
	return &WorkQueue{
		procs:          procs,
		needCandidates: needCandidates,
	}
}

func (wq *WorkQueue) enqueue(item interface{}) {
	wq.mu.Lock()
	defer wq.mu.Unlock()
	switch item := item.(type) {
	case *WorkTriage:
		if item.flags&ProgCandidate != 0 {
			wq.triageCandidate = append(wq.triageCandidate, item)
		} else {
			wq.triage = append(wq.triage, item)
		}
	case *WorkCandidate:
		wq.candidate = append(wq.candidate, item)
	case *WorkSmash:
		wq.smash = append(wq.smash, item)
	default:
		panic("unknown work type")
	}
}

func (wq *WorkQueue) dequeue() (item interface{}) {
	wq.mu.RLock()
	if len(wq.triageCandidate)+len(wq.candidate)+len(wq.triage)+len(wq.smash) == 0 {
		wq.mu.RUnlock()
		return nil
	}
	wq.mu.RUnlock()
	wq.mu.Lock()
	wantCandidates := false
	if len(wq.triageCandidate) != 0 {
		last := len(wq.triageCandidate) - 1
		item = wq.triageCandidate[last]
		wq.triageCandidate = wq.triageCandidate[:last]
	} else if len(wq.candidate) != 0 {
		last := len(wq.candidate) - 1
		item = wq.candidate[last]
		wq.candidate = wq.candidate[:last]
		wantCandidates = len(wq.candidate) < wq.procs
	} else if len(wq.triage) != 0 {
		last := len(wq.triage) - 1
		item = wq.triage[last]
		wq.triage = wq.triage[:last]
	} else if len(wq.smash) != 0 {
		last := len(wq.smash) - 1
		item = wq.smash[last]
		wq.smash = wq.smash[:last]
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

func (wq *WorkQueue) wantCandidates() bool {
	wq.mu.RLock()
	defer wq.mu.RUnlock()
	return len(wq.candidate) < wq.procs
}
