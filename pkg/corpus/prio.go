// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math/rand"
	"slices"
	"sort"

	"github.com/google/syzkaller/prog"
)

type ProgramsList struct {
	progs    []*prog.Prog
	sumPrios int64
	accPrios []int64
}

type focusAreaState struct {
	FocusArea
	*ProgramsList
	pcID     map[uint64]int
	pcCounts []int
	progPCs  [][]int
}

const (
	focusPCBudget        = 1000
	focusMaxEffectivePCs = 16
)

func (fas *focusAreaState) addProgPCs(p *prog.Prog, addedCover []uint64) bool {
	var matched []int
	for _, pc := range addedCover {
		if _, ok := fas.CoverPCs[pc]; !ok {
			continue
		}
		if fas.pcID == nil {
			fas.pcID = make(map[uint64]int)
		}
		id, ok := fas.pcID[pc]
		if !ok {
			id = len(fas.pcCounts)
			fas.pcID[pc] = id
			fas.pcCounts = append(fas.pcCounts, 0)
		}
		fas.pcCounts[id]++
		matched = append(matched, id)
	}
	if len(matched) == 0 {
		return false
	}
	idx := slices.Index(fas.progs, p)
	if idx < 0 {
		fas.saveProgram(p, 1)
		fas.progPCs = append(fas.progPCs, matched)
	} else {
		fas.progPCs[idx] = append(fas.progPCs[idx], matched...)
	}
	fas.recalcPrios()
	return true
}

func (fas *focusAreaState) recalcPrios() {
	var sum int64
	for i, pcs := range fas.progPCs {
		sumRarity := 0
		maxRarity := 0
		for _, id := range pcs {
			r := focusPCBudget / fas.pcCounts[id]
			sumRarity += r
			maxRarity = max(maxRarity, r)
		}
		prio := max(1, min(sumRarity, focusMaxEffectivePCs*maxRarity))
		sum += int64(prio)
		fas.accPrios[i] = sum
	}
	fas.sumPrios = sum
}

func (fas *focusAreaState) clear() {
	fas.ProgramsList.clear()
	fas.pcID = nil
	fas.pcCounts = nil
	fas.progPCs = nil
}

func (pl *ProgramsList) chooseProgram(r *rand.Rand) *prog.Prog {
	if len(pl.progs) == 0 {
		return nil
	}
	randVal := r.Int63n(pl.sumPrios) + 1
	idx := sort.Search(len(pl.accPrios), func(i int) bool {
		return pl.accPrios[i] >= randVal
	})
	return pl.progs[idx]
}

func (pl *ProgramsList) saveProgram(p *prog.Prog, prio int) {
	if prio == 0 {
		prio = 1
	}
	pl.sumPrios += int64(prio)
	pl.accPrios = append(pl.accPrios, pl.sumPrios)
	pl.progs = append(pl.progs, p)
}

func (pl *ProgramsList) addProgramPrio(p *prog.Prog, delta int) {
	if delta <= 0 {
		return
	}
	idx := slices.Index(pl.progs, p)
	if idx < 0 {
		pl.saveProgram(p, delta)
		return
	}
	pl.sumPrios += int64(delta)
	for i := idx; i < len(pl.accPrios); i++ {
		pl.accPrios[i] += int64(delta)
	}
}

func (corpus *Corpus) chooseFocusArea(r *rand.Rand) *focusAreaState {
	if len(corpus.focusAreas) == 0 {
		return nil
	}
	sum := 0.0
	nonEmpty := make([]*focusAreaState, 0, len(corpus.focusAreas))
	for _, area := range corpus.focusAreas {
		if len(area.progs) == 0 {
			continue
		}
		sum += area.Weight
		nonEmpty = append(nonEmpty, area)
	}
	val := r.Float64() * sum
	currSum := 0.0
	var randArea *focusAreaState
	for _, area := range nonEmpty {
		if val >= currSum {
			randArea = area
		}
		currSum += area.Weight
	}
	return randArea
}

func (corpus *Corpus) ChooseProgram(r *rand.Rand) *prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	if len(corpus.progsMap) == 0 {
		return nil
	}
	if randArea := corpus.chooseFocusArea(r); randArea != nil {
		return randArea.chooseProgram(r)
	}
	return corpus.chooseProgram(r)
}

func (corpus *Corpus) ChoosePrograms(r *rand.Rand) []*prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	if randArea := corpus.chooseFocusArea(r); randArea != nil {
		return randArea.progs
	}
	return corpus.progs
}

func (corpus *Corpus) Programs() []*prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progs
}

// FocusedPrograms returns programs belonging to specific focus areas (CoverPCs != nil).
func (corpus *Corpus) FocusedPrograms() []*prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.focusedProgs
}

func (pl *ProgramsList) clear() {
	// Set slices to nil rather than [:0] because Programs() and ChoosePrograms()
	// return pl.progs slice headers to callers that read them after releasing corpus.mu.
	pl.progs = nil
	pl.accPrios = nil
	pl.sumPrios = 0
}
