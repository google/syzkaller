// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"fmt"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

const (
	memAllocMaxMem = 16 << 20
)

type allocation struct {
	numBytes uint64
	arg      prog.Arg
}

// TODO: Replace memory tracker with memAlloc in prog package.
// Ask Dmitry the best way we should export that object
type memoryTracker struct {
	allocations map[*prog.Call][]*allocation
}

func newTracker() *memoryTracker {
	return &memoryTracker{
		allocations: make(map[*prog.Call][]*allocation),
	}
}

func (m *memoryTracker) addAllocation(call *prog.Call, size uint64, arg prog.Arg) {
	switch arg.(type) {
	case *prog.PointerArg:
	default:
		log.Fatalf("Adding allocation for non pointer")
	}
	alloc := new(allocation)
	alloc.arg = arg
	alloc.numBytes = size
	if _, ok := m.allocations[call]; !ok {
		m.allocations[call] = make([]*allocation, 0)
	}
	m.allocations[call] = append(m.allocations[call], alloc)
}

func (m *memoryTracker) fillOutMemory(prog *prog.Prog) (err error) {
	pageSize := prog.Target.PageSize
	var offset uint64
	if offset, err = m.fillOutPtrArgs(prog); err != nil {
		return
	}

	if offset%pageSize > 0 {
		offset = (offset/pageSize + 1) * pageSize
	}
	return nil
}

func (m *memoryTracker) fillOutPtrArgs(p *prog.Prog) (uint64, error) {
	offset := uint64(0)
	pageSize := p.Target.PageSize
	for _, call := range p.Calls {
		if _, ok := m.allocations[call]; !ok {
			continue
		}
		i := 0
		for _, a := range m.allocations[call] {
			switch arg := a.arg.(type) {
			case *prog.PointerArg:
				arg.Address = offset
				offset += a.numBytes
				i++
				if arg.Address >= memAllocMaxMem {
					return 0, fmt.Errorf("Unable to allocate space to store arg: %#v"+
						"in Call: %v. Required memory is larger than what we allow."+
						"Offending address: %d. Skipping program generation for this prog...\n",
						arg, call, arg.Address)
				}
			default:
				log.Fatalf("Pointer Arg Failed")
			}
		}
	}

	if offset%pageSize > 0 {
		offset = (offset/pageSize + 1) * pageSize
	}

	return offset, nil
}
