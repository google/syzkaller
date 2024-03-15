// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import "github.com/google/syzkaller/pkg/corpus"

const (
	statGenerate       = "exec gen"
	statFuzz           = "exec fuzz"
	statCandidate      = "exec candidate"
	statTriage         = "exec triage"
	statMinimize       = "exec minimize"
	statSmash          = "exec smash"
	statHint           = "exec hints"
	statSeed           = "exec seeds"
	statCollide        = "exec collide"
	statExecTotal      = "exec total"
	statBufferTooSmall = "buffer too small"
)

type Stats struct {
	CoverStats
	corpus.Stats
	Candidates  int
	RunningJobs int
	// Let's keep stats in Named as long as the rest of the code does not depend
	// on their specific values.
	Named map[string]uint64
}

func (fuzzer *Fuzzer) Stats() Stats {
	ret := Stats{
		CoverStats:  fuzzer.Cover.Stats(),
		Stats:       fuzzer.Config.Corpus.Stats(),
		Candidates:  int(fuzzer.queuedCandidates.Load()),
		RunningJobs: int(fuzzer.runningJobs.Load()),
		Named:       make(map[string]uint64),
	}
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	for k, v := range fuzzer.stats {
		ret.Named[k] = v
	}
	return ret
}
