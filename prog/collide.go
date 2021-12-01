// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Contains prog transformations that intend to trigger more races.

package prog

import (
	"fmt"
	"math/rand"
)

// The executor has no more than 32 threads that are used both for async calls and for calls
// that timed out. If we just ignore that limit, we could end up generating programs that
// would force the executor to fail and thus stall the fuzzing process.
// As an educated guess, let's use no more than 24 async calls to let executor handle everything.
const maxAsyncPerProg = 24

// Ensures that if an async call produces a resource, then
// it is distanced from a call consuming the resource at least
// by one non-async call.
// This does not give 100% guarantee that the async call finishes
// by that time, but hopefully this is enough for most cases.
func AssignRandomAsync(origProg *Prog, rand *rand.Rand) *Prog {
	var unassigned map[*ResultArg]bool
	leftAsync := maxAsyncPerProg
	prog := origProg.Clone()
	for i := len(prog.Calls) - 1; i >= 0 && leftAsync > 0; i-- {
		call := prog.Calls[i]
		producesUnassigned := false
		consumes := make(map[*ResultArg]bool)
		ForeachArg(call, func(arg Arg, ctx *ArgCtx) {
			res, ok := arg.(*ResultArg)
			if !ok {
				return
			}
			if res.Dir() != DirIn && unassigned[res] {
				// If this call is made async, at least one of the resources
				// will be empty when it's needed.
				producesUnassigned = true
			}
			if res.Dir() != DirOut {
				consumes[res.Res] = true
			}
		})
		// Make async with a 66% chance (but never the last call).
		if !producesUnassigned && i+1 != len(prog.Calls) && rand.Intn(3) != 0 {
			call.Props.Async = true
			for res := range consumes {
				unassigned[res] = true
			}
			leftAsync--
		} else {
			call.Props.Async = false
			unassigned = consumes
		}
	}

	return prog
}

var rerunSteps = []int{32, 64}

func AssignRandomRerun(prog *Prog, rand *rand.Rand) {
	for i := 0; i+1 < len(prog.Calls); i++ {
		if !prog.Calls[i].Props.Async || rand.Intn(4) != 0 {
			continue
		}
		// We assign rerun to consecutive pairs of calls, where the first call is async.
		// TODO: consider assigning rerun also to non-collided progs.
		rerun := rerunSteps[rand.Intn(len(rerunSteps))]
		prog.Calls[i].Props.Rerun = rerun
		prog.Calls[i+1].Props.Rerun = rerun
		i++
	}
}

// We append prog to itself, but let the second part only reference resource from the first one.
// Then we execute all the duplicated calls simultaneously.
// This somehow resembles the way the previous collide mode was implemented - a program was executed
// normally and then one more time again, while keeping resource values from the first execution and
// not waiting until every other call finishes.
func DoubleExecCollide(origProg *Prog, rand *rand.Rand) (*Prog, error) {
	if len(origProg.Calls)*2 > MaxCalls {
		return nil, fmt.Errorf("the prog is too big for the DoubleExecCollide transformation")
	}
	prog := origProg.Clone()
	dupCalls := cloneCalls(prog.Calls, nil)
	leftAsync := maxAsyncPerProg
	for _, c := range dupCalls {
		if leftAsync == 0 {
			break
		}
		c.Props.Async = true
		leftAsync--
	}
	prog.Calls = append(prog.Calls, dupCalls...)
	return prog, nil
}
