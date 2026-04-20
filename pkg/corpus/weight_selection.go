// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math/rand"
	"sort"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type SeedSelection interface {
	ChooseProgram(r *rand.Rand) *prog.Prog
	SaveProgram(p *prog.Prog, signal signal.Signal, cover []uint64)
	Programs() []*prog.Prog
	Empty() SeedSelection
}

func NewWeightedSelection() SeedSelection {
	return &WeightedSelection{}
}

type WeightedSelection struct {
	progs    []*prog.Prog
	sumPrios int64
	accPrios []int64
}

func (s *WeightedSelection) Empty() SeedSelection {
	return &WeightedSelection{}
}

func (s *WeightedSelection) ChooseProgram(r *rand.Rand) *prog.Prog {
	if len(s.progs) == 0 {
		return nil
	}
	randVal := r.Int63n(s.sumPrios) + 1
	idx := sort.Search(len(s.accPrios), func(i int) bool {
		return s.accPrios[i] >= randVal
	})
	return s.progs[idx]
}

func (s *WeightedSelection) SaveProgram(p *prog.Prog, signal signal.Signal, cover []uint64) {
	prio := int64(len(signal))
	if prio == 0 {
		prio = 1
	}
	s.sumPrios += prio
	s.accPrios = append(s.accPrios, s.sumPrios)
	s.progs = append(s.progs, p)
}

func (s *WeightedSelection) Programs() []*prog.Prog {
	return s.progs
}

func (corpus *Corpus) ChooseProgram(r *rand.Rand) *prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	if len(corpus.progsMap) == 0 {
		return nil
	}
	// We could have used an approach similar to chooseProgram(), but for small number
	// of focus areas that is an overkill.
	var randArea *focusAreaState
	if len(corpus.focusAreas) > 0 {
		sum := 0.0
		nonEmpty := make([]*focusAreaState, 0, len(corpus.focusAreas))
		for _, area := range corpus.focusAreas {
			if len(area.selection.Programs()) == 0 {
				continue
			}
			sum += area.Weight
			nonEmpty = append(nonEmpty, area)
		}
		val := r.Float64() * sum
		currSum := 0.0
		for _, area := range nonEmpty {
			if val >= currSum {
				randArea = area
			}
			currSum += area.Weight
		}
	}
	if randArea != nil {
		return randArea.selection.ChooseProgram(r)
	}
	return corpus.selection.ChooseProgram(r)
}

func (corpus *Corpus) Programs() []*prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.selection.Programs()
}
