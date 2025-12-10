// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
)

// CorpusMinimizer provides the interface needed to minimize a corpus.
type CorpusMinimizer struct {
	Corpus         *corpus.Corpus
	CorpusDB       *db.DB
	Cover          bool
	LastMinCorpus  int
	SaturatedCalls map[string]bool
	DisabledHashes map[string]struct{}
	PhaseCheck     func() bool // returns true if we should proceed with minimization
}

// Minimize performs corpus minimization if conditions are met.
// It should be called with appropriate locking in place.
func (cm *CorpusMinimizer) Minimize() int {
	// Don't minimize corpus until we have triaged all inputs from it.
	// During corpus triage it would happen very often since we are actively adding inputs,
	// and presumably the persistent corpus was reasonably minimal, and we don't use it for fuzzing yet.
	if cm.PhaseCheck != nil && !cm.PhaseCheck() {
		return cm.LastMinCorpus
	}
	currSize := cm.Corpus.StatProgs.Val()
	if currSize <= cm.LastMinCorpus*103/100 {
		return cm.LastMinCorpus
	}
	cm.Corpus.Minimize(cm.Cover)
	newSize := cm.Corpus.StatProgs.Val()

	log.Logf(1, "minimized corpus: %v -> %v", currSize, newSize)
	cm.LastMinCorpus = newSize

	// From time to time we get corpus explosion due to different reason:
	// generic bugs, per-OS bugs, problems with fallback coverage, kcov bugs, etc.
	// This has bad effect on the instance and especially on instances
	// connected via hub. Do some per-syscall sanity checking to prevent this.
	for call, info := range cm.Corpus.CallCover() {
		if cm.Cover {
			// If we have less than 1K inputs per this call,
			// accept all new inputs unconditionally.
			if info.Count < 1000 {
				continue
			}
			// If we have more than 3K already, don't accept any more.
			// Between 1K and 3K look at amount of coverage we are getting from these programs.
			// Empirically, real coverage for the most saturated syscalls is ~30-60
			// per program (even when we have a thousand of them). For explosion
			// case coverage tend to be much lower (~0.3-5 per program).
			if info.Count < 3000 && len(info.Cover)/info.Count >= 10 {
				continue
			}
		} else {
			// If we don't have real coverage, signal is weak.
			// If we have more than several hundreds, there is something wrong.
			if info.Count < 300 {
				continue
			}
		}
		if cm.SaturatedCalls[call] {
			continue
		}
		cm.SaturatedCalls[call] = true
		log.Logf(0, "coverage for %v has saturated, not accepting more inputs", call)
	}

	// Clean up the corpus database
	for key := range cm.CorpusDB.Records {
		ok1 := cm.Corpus.Item(key) != nil
		_, ok2 := cm.DisabledHashes[key]
		if !ok1 && !ok2 {
			cm.CorpusDB.Delete(key)
		}
	}
	if err := cm.CorpusDB.Flush(); err != nil {
		log.Fatalf("failed to save corpus database: %v", err)
	}
	cm.CorpusDB.BumpVersion(CurrentDBVersion)

	return newSize
}
