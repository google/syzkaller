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
	progIdx  map[*prog.Prog]int // index of the program in progs
}

// focusAreaState holds the programs of a focus area.
// If the area has CoverPCs, programs are weighted by the rarity of the area PCs they cover:
// each area PC contributes focusPCBudget/N to the priority of each of the N programs that
// cover it, so a few programs covering rare PCs are not drowned out by hundreds of programs
// covering the same hot PCs (e.g. a shared helper function).
// If the area has no CoverPCs, ProgramsList is shared with the corpus and is managed there.
type focusAreaState struct {
	FocusArea
	*ProgramsList

	pcCounts map[uint64]int // area PC -> number of programs covering it
	progPCs  [][]uint64     // area PCs covered by progs[i]
}

const (
	focusPCBudget = 1 << 20
	// A program's priority is capped at focusMaxEffectivePCs times its rarest PC contribution,
	// so that programs covering many hot PCs don't win over programs covering one rare PC.
	focusMaxEffectivePCs = 16
)

// addProgPCs records the area PCs among PCs newly covered by p.
// It returns whether the area has changed. The caller must call recalcPrios afterwards.
func (fas *focusAreaState) addProgPCs(p *prog.Prog, newCover []uint64) bool {
	if len(fas.CoverPCs) == 0 {
		return false
	}
	var matched []uint64
	for _, pc := range newCover {
		if _, ok := fas.CoverPCs[pc]; ok {
			matched = append(matched, pc)
		}
	}
	if len(matched) == 0 {
		return false
	}
	slices.Sort(matched)
	matched = slices.Compact(matched)
	if fas.pcCounts == nil {
		fas.pcCounts = make(map[uint64]int)
	}
	for _, pc := range matched {
		fas.pcCounts[pc]++
	}
	if idx, ok := fas.progIdx[p]; ok {
		fas.progPCs[idx] = append(fas.progPCs[idx], matched...)
	} else {
		fas.saveProgram(p, 1)
		fas.progPCs = append(fas.progPCs, matched)
	}
	return true
}

func (fas *focusAreaState) recalcPrios() {
	if len(fas.CoverPCs) == 0 {
		return
	}
	var sum int64
	for i, pcs := range fas.progPCs {
		var sumRarity, maxRarity int64
		for _, pc := range pcs {
			rarity := focusPCBudget / int64(fas.pcCounts[pc])
			sumRarity += rarity
			maxRarity = max(maxRarity, rarity)
		}
		sum += max(1, min(sumRarity, focusMaxEffectivePCs*maxRarity))
		fas.accPrios[i] = sum
	}
	fas.sumPrios = sum
}

func (fas *focusAreaState) clear() {
	fas.ProgramsList.clear()
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
	if pl.progIdx == nil {
		pl.progIdx = make(map[*prog.Prog]int)
	}
	pl.progIdx[p] = len(pl.progs)
	pl.sumPrios += int64(prio)
	pl.accPrios = append(pl.accPrios, pl.sumPrios)
	pl.progs = append(pl.progs, p)
}

// addProgramPrio increases priority of an existing program p by delta.
// It's linear in the number of programs after p, but existing programs gain
// signal rarely compared to how often chooseProgram() is called, so it's cheaper
// to keep accPrios exact than to make chooseProgram() slower.
func (pl *ProgramsList) addProgramPrio(p *prog.Prog, delta int) {
	idx, ok := pl.progIdx[p]
	if !ok {
		panic("addProgramPrio for an unknown program")
	}
	if delta <= 0 {
		return
	}
	pl.sumPrios += int64(delta)
	for i := idx; i < len(pl.accPrios); i++ {
		pl.accPrios[i] += int64(delta)
	}
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
			if len(area.progs) == 0 {
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
		return randArea.chooseProgram(r)
	}
	return corpus.chooseProgram(r)
}

func (corpus *Corpus) Programs() []*prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progs
}

func (pl *ProgramsList) clear() {
	pl.progs = nil
	pl.accPrios = nil
	pl.sumPrios = 0
	pl.progIdx = nil
}
