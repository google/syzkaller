// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"cmp"
	"slices"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
)

// focusTier holds the triage and mutation job queues for a group of inputs.
// In the patch testing mode, there's a separate tier for each focus area with CoverPCs,
// so that inputs that reach the patched code are triaged and mutated with priority.
// Otherwise, all inputs share the single catch-all tier.
type focusTier struct {
	weight   float64
	coverPCs map[uint64]struct{}
	// Beginnings of the signal.PCRange ranges that contain coverPCs.
	signalRanges map[uint64]struct{}
	// If not set, inputs are only saved to the corpus, but not minimized and mutated.
	inFocus bool
	// Limit on the number of concurrently running hints jobs (0 means no limit).
	maxHintsJobs int64
	hintsJobs    atomic.Int64 // number of running hints jobs
	triageQueue  *queue.DynamicOrderer
	smashQueue   *queue.PlainQueue
	hintsQueue   *queue.PlainQueue
}

func newFocusTier(weight float64) *focusTier {
	return &focusTier{
		weight:      weight,
		inFocus:     true,
		triageQueue: queue.DynamicOrder(),
		smashQueue:  queue.Plain(),
		hintsQueue:  queue.Plain(),
	}
}

// In the patch testing mode, candidate triage may start thousands of hints jobs at once,
// and each of them can run for a long time. Limit the number of hints jobs per tier.
const maxPatchTestHintsJobs = 30

// newFocusTiers creates a tier per focus area with CoverPCs in the patch testing mode
// (plus the catch-all tier), or just the catch-all tier otherwise.
func newFocusTiers(cfg *Config) []*focusTier {
	catchAll := newFocusTier(1.0)
	if !cfg.PatchTest {
		return []*focusTier{catchAll}
	}
	areas := cfg.Corpus.FocusAreas()
	slices.SortStableFunc(areas, func(a, b corpus.FocusArea) int {
		return cmp.Compare(b.Weight, a.Weight)
	})
	var tiers []*focusTier
	for _, area := range areas {
		if area.Weight <= 0 {
			continue
		}
		if len(area.CoverPCs) == 0 {
			// The area of the whole corpus (there's at most one such area).
			catchAll.weight = area.Weight
			continue
		}
		tier := newFocusTier(area.Weight)
		tier.coverPCs = area.CoverPCs
		tier.signalRanges = make(map[uint64]struct{})
		for pc := range area.CoverPCs {
			begin, _ := signal.PCRange(pc)
			tier.signalRanges[begin] = struct{}{}
		}
		tier.maxHintsJobs = maxPatchTestHintsJobs
		tiers = append(tiers, tier)
	}
	// We don't want to spend time on inputs that don't reach the focus areas
	// (unless there are no focus areas at all).
	catchAll.inFocus = len(tiers) == 0
	catchAll.maxHintsJobs = maxPatchTestHintsJobs
	return append(tiers, catchAll)
}

// shouldSmash returns whether an input with the triage flags needs to be smashed.
func (tier *focusTier) shouldSmash(flags ProgFlags) bool {
	if !tier.inFocus {
		return false
	}
	// Programs that reach a focus area are smashed even if they were smashed before
	// (e.g. corpus candidates in the patch testing mode) since the focus area is new.
	return flags&ProgSmashed == 0 || len(tier.coverPCs) != 0
}

func (tier *focusTier) shouldStartHints() bool {
	return tier.maxHintsJobs == 0 || tier.hintsJobs.Load() < tier.maxHintsJobs
}

// mayCover returns whether the signal may include PCs from the tier's focus area.
// Signal elements only approximately identify PCs (see signal.PCRange), so this may
// return true for signal from unrelated code close to the focus area.
func (tier *focusTier) mayCover(sig signal.Signal) bool {
	for e := range sig {
		begin, _ := signal.PCRange(uint64(e))
		if _, ok := tier.signalRanges[begin]; ok {
			return true
		}
	}
	return false
}

func (tier *focusTier) covers(cov cover.Cover) bool {
	for pc := range cov {
		if _, ok := tier.coverPCs[pc]; ok {
			return true
		}
	}
	return false
}

func (fuzzer *Fuzzer) catchAllTier() *focusTier {
	return fuzzer.tiers[len(fuzzer.tiers)-1]
}

// triageQueueForCalls returns the triage queue of the highest priority tier
// whose focus area may be reached by the new signal.
func (fuzzer *Fuzzer) triageQueueForCalls(triage map[int]*triageCall) *queue.DynamicOrderer {
	for _, tier := range fuzzer.tiers[:len(fuzzer.tiers)-1] {
		for _, call := range triage {
			if tier.mayCover(call.newSignal) {
				return tier.triageQueue
			}
		}
	}
	return fuzzer.catchAllTier().triageQueue
}

// tierForCall returns the highest priority tier whose focus area is covered by the call.
func (fuzzer *Fuzzer) tierForCall(info *triageCall) *focusTier {
	for _, tier := range fuzzer.tiers[:len(fuzzer.tiers)-1] {
		if tier.covers(info.cover) {
			return tier
		}
	}
	return fuzzer.catchAllTier()
}
