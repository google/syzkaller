// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math/rand"
	"sort"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type ProgramsList struct {
	progs    []*prog.Prog
	sumPrios int64
	accPrios []int64
}

func (pl *ProgramsList) chooseProgram(r *rand.Rand) *prog.Prog {
	if len(pl.progs) == 0 {
		return nil
	}
	randVal := r.Int63n(pl.sumPrios + 1)
	idx := sort.Search(len(pl.accPrios), func(i int) bool {
		return pl.accPrios[i] >= randVal
	})
	return pl.progs[idx]
}

func (pl *ProgramsList) saveProgram(p *prog.Prog, signal signal.Signal) {
	prio := int64(len(signal))
	if prio == 0 {
		prio = 1
	}
	pl.sumPrios += prio
	pl.accPrios = append(pl.accPrios, pl.sumPrios)
	pl.progs = append(pl.progs, p)
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
