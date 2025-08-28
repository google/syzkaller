// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
)

func callHasDependents(p *Prog, idx int) bool {
	if !p.EnforceDeps {
		return false
	}
	hasDeps := false
	c := p.Calls[idx]
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		if a, ok := arg.(*ResultArg); ok {
			if len(a.uses) > 0 && (a.Dir() == DirOut || a.Dir() == DirInOut) {
				for key, val := range a.uses {
					if val && key.ArgCommon.dir == DirIn {
						hasDeps = true
						return
					}
				}
			}
		}
	})
	return hasDeps
}

func resizeGeneratedCalls(p *Prog, ncalls int, skipCall *Call) int {
	idxToRemove := len(p.Calls) - 1
	forceRemoval := false
	if idxToRemove < 0 {
		return 0
	}
	removed := 0
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
		if !forceRemoval && p.EnforceDeps && callHasDependents(p, idxToRemove) {
			removeCall = false
		}
		if removeCall {
			p.RemoveCall(idxToRemove)
			removed++
		}

		idxToRemove--
	}
	return removed
}

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	r := newRand(target, rs)
	p := &Prog{
		Target:      target,
		EnforceDeps: r.nOutOf(7, 10),
	}

	s := newState(target, ct, nil)
	r.EnforceDeps = p.EnforceDeps

	for len(p.Calls) < ncalls {
		clearSyscallStack(s)
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
	resizeGeneratedCalls(p, ncalls, nil)
	p.sanitizeFix()
	p.debugValidate()
	return p
}
