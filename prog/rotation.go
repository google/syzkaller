// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"sort"
)

// Rotator selects a random subset of syscalls for corpus rotation.
type Rotator struct {
	target        *Target
	calls         map[*Syscall]bool
	rnd           *rand.Rand
	resourceless  []*Syscall
	syscallUses   map[*Syscall][]*ResourceDesc
	resources     map[*ResourceDesc]rotatorResource
	goal          int
	nresourceless int
}

type rotatorResource struct {
	// 0 - precise ctors that don't require other resources as inputs (e.g. socket).
	// 1 - precise ctors that require other resources (e.g. accept).
	// 2 - all imprecise ctors.
	ctors [3][]*Syscall
	// 0 - precise uses of this resource.
	// 1 - uses of parent resources (e.g. close for sock).
	uses [2][]*Syscall
}

func MakeRotator(target *Target, calls map[*Syscall]bool, rnd *rand.Rand) *Rotator {
	r := &Rotator{
		target:      target,
		calls:       calls,
		rnd:         rnd,
		syscallUses: make(map[*Syscall][]*ResourceDesc),
		resources:   make(map[*ResourceDesc]rotatorResource),
	}
	for call := range calls {
		r.syscallUses[call] = append(r.syscallUses[call], call.inputResources...)
		r.syscallUses[call] = append(r.syscallUses[call], call.outputResources...)
		var inputs []*ResourceDesc
		for _, res := range call.inputResources {
			// Don't take into account pid/uid/etc, they create too many links.
			if !target.AuxResources[res.Name] {
				inputs = append(inputs, res)
			}
		}
		// VMAs and filenames are effectively resources for our purposes
		// (but they don't have ctors).
		ForeachType(call, func(t Type) {
			switch a := t.(type) {
			case *BufferType:
				switch a.Kind {
				case BufferFilename:
					inputs = append(inputs, filenameRes)
				}
			case *VmaType:
				inputs = append(inputs, vmaRes)
			}
		})

		inputDedup := make(map[string]bool, len(inputs))
		for _, res := range inputs {
			if inputDedup[res.Name] {
				continue
			}
			inputDedup[res.Name] = true
			info := r.resources[res]
			info.uses[0] = append(info.uses[0], call)
			r.resources[res] = info

			for _, kind := range res.Kind[:len(res.Kind)-1] {
				parent := target.resourceMap[kind]
				info := r.resources[parent]
				info.uses[1] = append(info.uses[1], call)
				r.resources[parent] = info
			}
		}
		outputDedup := make(map[string]bool, len(call.outputResources))
		for _, res := range call.outputResources {
			if outputDedup[res.Name] {
				continue
			}
			outputDedup[res.Name] = true
			info := r.resources[res]
			class := 0
			if len(inputs) != 0 {
				class = 1
			}
			info.ctors[class] = append(info.ctors[class], call)
			r.resources[res] = info
			for _, kind := range res.Kind[:len(res.Kind)-1] {
				parent := target.resourceMap[kind]
				info := r.resources[parent]
				info.ctors[2] = append(info.ctors[2], call)
				r.resources[parent] = info
			}
		}
		if len(inputs)+len(call.outputResources) == 0 {
			r.resourceless = append(r.resourceless, call)
		}
	}
	// For smaller syscall sets we drop ~5% of syscalls.
	// However, we assume that 200 syscalls is enough for a fuzzing session,
	// so we cap at that level to make fuzzing more targeted.
	r.goal = len(calls) * 19 / 20
	if r.goal < 1 {
		r.goal = 1
	}
	if max := 200; r.goal > max {
		r.goal = max
	}
	// How many syscalls that don't use any resources we want to add?
	r.nresourceless = r.goal * len(r.resourceless) / len(calls)
	if r.nresourceless < 1 {
		r.nresourceless = 1
	}
	return r
}

func (r *Rotator) Select() map[*Syscall]bool {
	rs := rotatorState{
		Rotator: r,
		calls:   make(map[*Syscall]bool, 3*r.goal),
	}
	return rs.Select()
}

type rotatorState struct {
	*Rotator
	calls      map[*Syscall]bool
	topQueue   []*ResourceDesc
	depQueue   []*ResourceDesc
	topHandled map[*ResourceDesc]bool
	depHandled map[*ResourceDesc]bool
}

func (rs *rotatorState) Select() map[*Syscall]bool {
	// The algorithm is centered around resources.
	// But first we add some syscalls that don't use any resources at all
	// Otherwise we will never add them in the loop.
	// Then, we select a resource and add some ctors for this resources
	// and some calls that use it. That's handled by topQueue.
	// If any of the calls require other resources as inputs, we also add
	// some ctors for these resources, but don't add calls that use them.
	// That's handled by depQueue.
	// However, a resource can be handled as dependency first, but then
	// handled as top resource again. In such case we will still add calls
	// that use this resource.
	for {
		if len(rs.depQueue) == 0 && len(rs.calls) >= rs.goal || len(rs.calls) >= 2*rs.goal {
			rs.calls, _ = rs.target.transitivelyEnabled(rs.calls)
			if len(rs.calls) >= rs.goal {
				return rs.calls
			}
		}
		if len(rs.depQueue) != 0 {
			// Handle a dependent resource, add only ctors for these.
			// Pick a random one, this gives a mix of DFS and BFS.
			idx := rs.rnd.Intn(len(rs.depQueue))
			res := rs.depQueue[idx]
			rs.depQueue[idx] = rs.depQueue[len(rs.depQueue)-1]
			rs.depQueue = rs.depQueue[:len(rs.depQueue)-1]
			info := rs.resources[res]
			nctors0 := len(info.ctors[0]) != 0
			nctors1 := nctors0 || len(info.ctors[1]) != 0
			rs.selectCalls(info.ctors[0], 2, true)
			if nctors0 {
				continue
			}
			rs.selectCalls(info.ctors[1], 2, !nctors0)
			if nctors1 {
				continue
			}
			rs.selectCalls(info.ctors[0], 2, !nctors1)
			continue
		}
		if len(rs.topQueue) == 0 {
			// We either just started selection or we handled all resources,
			// but did not gather enough syscalls. In both cases we need
			// to reset all queues.
			rs.topQueue = make([]*ResourceDesc, 0, len(rs.resources))
			rs.depQueue = make([]*ResourceDesc, 0, len(rs.resources))
			rs.topHandled = make(map[*ResourceDesc]bool, len(rs.resources))
			rs.depHandled = make(map[*ResourceDesc]bool, len(rs.resources))
			for res := range rs.resources {
				rs.topQueue = append(rs.topQueue, res)
			}
			sort.Slice(rs.topQueue, func(i, j int) bool {
				return rs.topQueue[i].Name < rs.topQueue[j].Name
			})
			rs.rnd.Shuffle(len(rs.topQueue), func(i, j int) {
				rs.topQueue[i], rs.topQueue[j] = rs.topQueue[j], rs.topQueue[i]
			})
			rs.selectCalls(rs.resourceless, rs.nresourceless+1, false)
		}
		// Handle a top resource, add more syscalls for these.
		res := rs.topQueue[0]
		rs.topQueue = rs.topQueue[1:]
		if rs.topHandled[res] {
			panic("top queue already handled")
		}
		rs.topHandled[res] = true
		info := rs.resources[res]
		nctors0 := len(info.ctors[0]) != 0
		nctors1 := nctors0 || len(info.ctors[1]) != 0
		rs.selectCalls(info.ctors[0], 5, true)
		rs.selectCalls(info.ctors[1], 3, !nctors0)
		rs.selectCalls(info.ctors[0], 2, !nctors1)
		rs.selectCalls(info.uses[0], 20, true)
		rs.selectCalls(info.uses[1], 2, len(info.uses[0]) == 0)
	}
}

func (rs *rotatorState) addCall(call *Syscall) {
	if rs.calls[call] {
		return
	}
	rs.calls[call] = true
	for _, res := range rs.syscallUses[call] {
		if rs.topHandled[res] || rs.depHandled[res] {
			continue
		}
		rs.depHandled[res] = true
		rs.depQueue = append(rs.depQueue, res)
	}
}

func (rs *rotatorState) selectCalls(set []*Syscall, probability int, force bool) {
	if !force && probability < 2 {
		panic("will never select anything")
	}
	for ; len(set) != 0 && (force || rs.rnd.Intn(probability) != 0); force = false {
		call := set[rs.rnd.Intn(len(set))]
		rs.addCall(call)
	}
}
