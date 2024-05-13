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
	for _, inp := range corpus.progs {
		inputs = append(inputs, signal.Context{
			Signal:  inp.Signal,
			Context: inp,
		})
	}

	// Note: inputs are unsorted (based on map iteration).
	// This gives some intentional non-determinism during minimization.
	// However, we want to give preference to non-squashed inputs,
	// so let's sort by this criteria.
	sort.SliceStable(inputs, func(i, j int) bool {
		firstAny := inputs[i].Context.(*Item).HasAny
		secondAny := inputs[j].Context.(*Item).HasAny
		return !firstAny && secondAny
	})

	corpus.progs = make(map[string]*Item)
	programsList := &ProgramsList{}
	for _, ctx := range signal.Minimize(inputs) {
		inp := ctx.(*Item)
		corpus.progs[inp.Sig] = inp
		programsList.saveProgram(inp.Prog, inp.Signal)
	}
	corpus.ProgramsList.replace(programsList)
}
