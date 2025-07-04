// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
)

func resizeGeneratedCalls(p *Prog, ncalls int, skipCall *Call) {
	idxToRemove := len(p.Calls) - 1
	forceRemoval := false
	if idxToRemove < 0 {
		return
	}

	for len(p.Calls) > ncalls {
		if idxToRemove < 0 {
			// We tried to keep dependencies, but we have to remove something.
			forceRemoval = true
			idxToRemove = len(p.Calls) - 1
		}
		if skipCall != nil && p.Calls[idxToRemove] == skipCall {
			idxToRemove--
			continue
		}
		removeCall := true
		if IsPromoteDeps() && !forceRemoval {
			p1 := p.Clone()
			p1.RemoveCall(idxToRemove)
			if !p1.ValidateDeps() {
				removeCall = false
			}
		}
		if removeCall {
			p.RemoveCall(idxToRemove) // it used to be (ncalls-1), but it would remove random dependencies
		}

		idxToRemove--
	}
}

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for len(p.Calls) < ncalls {
		clearIoctlStack(s)
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	allowCalls := ncalls
	if IsPromoteDeps() {
		// if we promote depenendencies, and the program is within limits,
		// we'll allow it as is
		allowCalls = max(MaxCalls, ncalls)
	}
	resizeGeneratedCalls(p, allowCalls, nil)
	p.sanitizeFix()
	p.debugValidate()
	return p
}
