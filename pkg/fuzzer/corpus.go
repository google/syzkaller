// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"
	"sort"
	"sync"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type Corpus struct {
	mu        sync.RWMutex
	progs     []*prog.Prog
	hashes    map[hash.Sig]struct{}
	sumPrios  int64
	accPrios  []int64
	signal    signal.Signal // signal of inputs in corpus
	maxSignal signal.Signal // max signal ever observed (including flakes)
	newSignal signal.Signal
}

// CorpusStat is a snapshot of the relevant current state figures.
type CorpusStat struct {
	Progs     int
	Signal    int
	MaxSignal int
}

func newCorpus() *Corpus {
	return &Corpus{
		hashes: make(map[hash.Sig]struct{}),
	}
}

// TODO: maybe we want to treat progs from other fuzzers exactly like
// candidates? And even triage them?
func (corpus *Corpus) Save(p *prog.Prog, signal signal.Signal, sig hash.Sig) {
	corpus.mu.Lock()
	defer corpus.mu.Unlock()
	if _, ok := corpus.hashes[sig]; !ok {
		corpus.progs = append(corpus.progs, p)
		corpus.hashes[sig] = struct{}{}
		prio := int64(len(signal))
		if prio == 0 {
			prio = 1
		}
		corpus.sumPrios += prio
		corpus.accPrios = append(corpus.accPrios, corpus.sumPrios)
	}
	corpus.signal.Merge(signal)
	corpus.maxSignal.Merge(signal)
}

// Signal that should no longer be chased after.
func (corpus *Corpus) AddMaxSignal(sign signal.Signal) {
	// TODO: how do we ensure occasional drop of this max cover?
	corpus.mu.Lock()
	defer corpus.mu.Unlock()
	corpus.maxSignal.Merge(sign)
}

func (corpus *Corpus) AddRawMaxSignal(signal []uint32, prio uint8) signal.Signal {
	corpus.mu.Lock()
	defer corpus.mu.Unlock()
	diff := corpus.maxSignal.DiffRaw(signal, prio)
	if diff.Empty() {
		return diff
	}
	corpus.maxSignal.Merge(diff)
	corpus.newSignal.Merge(diff)
	return diff
}

func (corpus *Corpus) chooseProgram(r *rand.Rand) *prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	if len(corpus.progs) == 0 {
		return nil
	}
	randVal := r.Int63n(corpus.sumPrios + 1)
	idx := sort.Search(len(corpus.accPrios), func(i int) bool {
		return corpus.accPrios[i] >= randVal
	})
	return corpus.progs[idx]
}

func (corpus *Corpus) Programs() []*prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progs
}

func (corpus *Corpus) GrabNewSignal() signal.Signal {
	corpus.mu.Lock()
	defer corpus.mu.Unlock()
	sign := corpus.newSignal
	corpus.newSignal = nil
	return sign
}

func (corpus *Corpus) Stat() CorpusStat {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return CorpusStat{
		Progs:     len(corpus.progs),
		Signal:    len(corpus.signal),
		MaxSignal: len(corpus.maxSignal),
	}
}
