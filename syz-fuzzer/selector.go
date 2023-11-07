// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand"
	"sync"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type progSelector struct {
	perHashProgs map[uint32][]*prog.Prog
	allHashes    []uint32
	noHashes     []*prog.Prog
	mu           sync.RWMutex
}

func (ps *progSelector) addInput(p *prog.Prog, hashes signal.Signal) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if hashes.Empty() {
		// We cannot do any better than just store such inputs separately.
		ps.noHashes = append(ps.noHashes, p)
		return
	}
	if ps.perHashProgs == nil {
		// Let's do lazy init to simplify object construction.
		ps.perHashProgs = map[uint32][]*prog.Prog{}
	}
	// Update each hash from the signal.
	for hashRaw := range hashes.Serialize().Elems {
		hash := uint32(hashRaw)
		old, ok := ps.perHashProgs[hash]
		if !ok {
			ps.allHashes = append(ps.allHashes, hash)
			// Let's reduce load on the allocator/garbage collector.
			const startCapacity = 4
			ps.perHashProgs[hash] = make([]*prog.Prog, 0, startCapacity)
		}
		// If a hash is covered by many progs already, it does not matter
		// anymore by how many exactly.
		const perHashLimit = 32
		if len(old) >= perHashLimit {
			continue
		}
		ps.perHashProgs[hash] = append(old, p)
	}
}

func (ps *progSelector) chooseProgram(r *rand.Rand) *prog.Prog {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	total := len(ps.allHashes)
	if total == 0 {
		// Select one of the inputs without signal then.
		if len(ps.noHashes) > 0 {
			return ps.noHashes[r.Intn(len(ps.noHashes))]
		}
		return nil
	}
	// In general, we want to distribute weights inversely proportional to
	// the number of progs that cover a specific hash.
	// It's much easier in practice to approximate it by randomly selecting
	// several hashes and picking the least covered one.

	// For Linux, ~25% of PCs are covered by just one program, so let's
	// randomize the number of selections to give all counts a chance.
	attempts := 1 + r.Intn(4)

	var smallestProgs []*prog.Prog
	for i := 0; i < attempts; i++ {
		hash := ps.allHashes[r.Intn(total)]
		progs := ps.perHashProgs[hash]
		if len(smallestProgs) == 0 || len(smallestProgs) > len(progs) {
			smallestProgs = progs
		}
	}
	if len(smallestProgs) == 0 {
		// This should never happen.
		panic("smallestProgs is empty")
	}
	return smallestProgs[r.Intn(len(smallestProgs))]
}
