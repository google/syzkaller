// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"fmt"

	"github.com/google/syzkaller/prog"
)

const (
	memAllocMaxMem = 16 << 20
)

type allocation struct {
	numBytes uint64
	arg      *prog.PointerArg
}

// TODO: Replace memory tracker with memAlloc in prog package.
type memoryTracker struct {
	allocations map[*prog.Call][]*allocation
}

func newTracker() *memoryTracker {
	return &memoryTracker{
		allocations: make(map[*prog.Call][]*allocation),
	}
}

func (m *memoryTracker) addAllocation(call *prog.Call, size uint64, arg *prog.PointerArg) {
	alloc := new(allocation)
	alloc.arg = arg
	alloc.numBytes = size

	if _, ok := m.allocations[call]; !ok {
		m.allocations[call] = make([]*allocation, 0)
	}
	m.allocations[call] = append(m.allocations[call], alloc)
}

func (m *memoryTracker) fillOutPtrArgs(p *prog.Prog) error {
	offset := uint64(0)
	for _, call := range p.Calls {
		if _, ok := m.allocations[call]; !ok {
			continue
		}
		for _, a := range m.allocations[call] {
			a.arg.Address = offset
			offset += a.numBytes

			if a.arg.Address >= memAllocMaxMem {
				return fmt.Errorf("unable to allocate space to store arg: %#v"+
					"in Call: %v. Required memory is larger than what we allow."+
					"Offending address: %d. Skipping program generation for this prog...\n",
					a.arg, call, a.arg.Address)
			}
		}
	}
	return nil
}
