// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

func NewWeightedPCSelection() SeedSelection {
	return &WeightedPCSelection{
		pcMap: make(map[uint64]int),
	}
}

type WeightedPCSelection struct {
	tree     []weightedPCNode
	pcMap    map[uint64]int
	allProgs []*prog.Prog
}

type weightedPCNode struct {
	selection *WeightedSelection
	weight    float64
	sum       float64
}

func (s *WeightedPCSelection) ChooseProgram(r *rand.Rand) *prog.Prog {
	if len(s.tree) == 0 {
		return nil
	}
	idx := 0
	val := r.Float64() * s.tree[0].sum
	for {
		// Try left child.
		left := 2*idx + 1
		if left < len(s.tree) {
			if val < s.tree[left].sum {
				idx = left
				continue
			}
			val -= s.tree[left].sum
		}

		// Try current node.
		if val < s.tree[idx].weight {
			return s.tree[idx].selection.ChooseProgram(r)
		}
		val -= s.tree[idx].weight

		// Try right child.
		right := 2*idx + 2
		if right < len(s.tree) {
			idx = right
			continue
		}

		// Fallback for floating point errors or edge cases: pick current.
		return s.tree[idx].selection.ChooseProgram(r)
	}
}

func (s *WeightedPCSelection) SaveProgram(p *prog.Prog, signal signal.Signal, cover []uint64) {
	if s.pcMap == nil {
		s.pcMap = make(map[uint64]int)
	}
	for _, pc := range cover {
		idx, ok := s.pcMap[pc]
		if !ok {
			idx = len(s.tree)
			s.pcMap[pc] = idx
			s.tree = append(s.tree, weightedPCNode{
				selection: &WeightedSelection{},
			})
		}
		// Update selection for this PC.
		node := &s.tree[idx]
		node.selection.SaveProgram(p, signal, nil)
		// Update weight (1.0 / count).
		node.weight = 1.0 / float64(len(node.selection.progs))

		// Propagate sum updates up to the root.
		s.updateSum(idx)
	}
	s.allProgs = append(s.allProgs, p)
}

func (s *WeightedPCSelection) updateSum(idx int) {
	for {
		node := &s.tree[idx]
		sum := node.weight
		left := 2*idx + 1
		if left < len(s.tree) {
			sum += s.tree[left].sum
		}
		right := 2*idx + 2
		if right < len(s.tree) {
			sum += s.tree[right].sum
		}
		node.sum = sum

		if idx == 0 {
			break
		}
		idx = (idx - 1) / 2
	}
}

func (s *WeightedPCSelection) Programs() []*prog.Prog {
	return s.allProgs
}

func (s *WeightedPCSelection) Empty() SeedSelection {
	return NewWeightedPCSelection()
}
