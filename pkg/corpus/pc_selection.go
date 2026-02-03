// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

func NewRandomPCSelection() SeedSelection {
	return &RandomPCSelection{}
}

type RandomPCSelection struct {
	pcMap    map[uint64]*WeightedSelection
	pcs      []uint64
	allProgs []*prog.Prog
}

func (s *RandomPCSelection) ChooseProgram(r *rand.Rand) *prog.Prog {
	if len(s.pcs) == 0 {
		return nil
	}
	pc := s.pcs[r.Intn(len(s.pcs))]
	return s.pcMap[pc].ChooseProgram(r)
}

func (s *RandomPCSelection) SaveProgram(p *prog.Prog, signal signal.Signal, cover []uint64) {
	if s.pcMap == nil {
		s.pcMap = make(map[uint64]*WeightedSelection)
	}
	for _, pc := range cover {
		sel := s.pcMap[pc]
		if sel == nil {
			sel = &WeightedSelection{}
			s.pcMap[pc] = sel
			s.pcs = append(s.pcs, pc)
		}
		sel.SaveProgram(p, signal, nil)
	}
	s.allProgs = append(s.allProgs, p)
}

func (s *RandomPCSelection) Programs() []*prog.Prog {
	return s.allProgs
}

func (s *RandomPCSelection) Empty() SeedSelection {
	return &RandomPCSelection{}
}
