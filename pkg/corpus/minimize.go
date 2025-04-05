// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"sort"

	"github.com/google/syzkaller/pkg/signal"
)

func (corpus *Corpus) Minimize(cover bool) {
	corpus.mu.Lock()
	defer corpus.mu.Unlock()

	inputs := make([]signal.Context, 0, len(corpus.progs))
	for _, inp := range corpus.progsMap {
		inputs = append(inputs, signal.Context{
			Signal:  inp.Signal,
			Context: inp,
		})
	}

	// Note: inputs are unsorted (based on map iteration).
	// This gives some intentional non-determinism during minimization.
	// However, we want to give preference to non-squashed inputs,
	// so let's sort by this criteria.
	// We also want to give preference to smaller corpus programs:
	// - they are faster to execute,
	// - minimization occasionally fails, so we need to clean it up over time.
	sort.SliceStable(inputs, func(i, j int) bool {
		first := inputs[i].Context.(*Item)
		second := inputs[j].Context.(*Item)
		if first.HasAny != second.HasAny {
			return !first.HasAny
		}
		return len(first.Prog.Calls) < len(second.Prog.Calls)
	})

	corpus.progsMap = make(map[string]*Item)

	// Overwrite the program lists.
	corpus.ProgramsList = &ProgramsList{}
	for _, area := range corpus.focusAreas {
		area.ProgramsList = &ProgramsList{}
	}
	for _, ctx := range signal.Minimize(inputs) {
		inp := ctx.(*Item)
		corpus.progsMap[inp.Sig] = inp
		corpus.saveProgram(inp.Prog, inp.Signal)
		for area := range inp.areas {
			area.saveProgram(inp.Prog, inp.Signal)
		}
	}
}
