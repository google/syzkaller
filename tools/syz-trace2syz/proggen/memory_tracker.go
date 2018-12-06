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
	m.allocations[call] = append(m.allocations[call], &allocation{
		arg:      arg,
		numBytes: size,
	})
}

func (m *memoryTracker) fillOutPtrArgs(p *prog.Prog) error {
	var offset uint64
	for _, call := range p.Calls {
		for _, a := range m.allocations[call] {
			a.arg.Address = offset
			offset += a.numBytes

			if a.arg.Address >= memAllocMaxMem {
				return fmt.Errorf("unable to allocate space to store arg: %#v"+
					"in Call: %v. Required memory is larger than what we allow."+
					"Offending address: %v",
					a.arg, call, a.arg.Address)
			}
		}
	}
	return nil
}
