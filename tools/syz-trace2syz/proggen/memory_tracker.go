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

// Memory dependency represents the dependency of a call on a
// virtual memory mapping. We assume the dependency is contiguous
// as we will allocate pointers for arguments in a separate mmap at the
// beginning of the function. Moreover there are no calls which we know of
// that take a list of pages as arguments.

type memDependency struct {
	Callidx int
	arg     prog.Arg
	start   uint64
	end     uint64
}

func newMemDependency(callidx int, usedBy prog.Arg, start uint64, end uint64) *memDependency {
	return &memDependency{
		Callidx: callidx,
		arg:     usedBy,
		start:   start,
		end:     end,
	}
}

type virtualMapping struct {
	usedBy    []*memDependency
	createdBy *prog.Call
	callidx   int
	start     uint64
	end       uint64
}

type shmRequest struct {
	size  uint64
	shmid uint64
}

func (s *shmRequest) getSize() uint64 {
	return s.size
}

func (vm *virtualMapping) getUsedBy() []*memDependency {
	return vm.usedBy
}

func (vm *virtualMapping) addDependency(md *memDependency) {
	vm.usedBy = append(vm.usedBy, md)
}

func (vm *virtualMapping) getEnd() uint64 {
	return vm.end
}

func (vm *virtualMapping) getStart() uint64 {
	return vm.start
}

func (vm *virtualMapping) getCall() *prog.Call {
	return vm.createdBy
}

func (vm *virtualMapping) getCallIdx() int {
	return vm.callidx
}

// TODO: Replace memory tracker with memAlloc in prog package.
// Ask Dmitry the best way we should export that object
type memoryTracker struct {
	allocations map[*prog.Call][]*allocation
	mappings    []*virtualMapping

	// We keep the SYSTEM V shared mapping requests because
	// the creation of memory is broken into two steps: shmget, shmat
	// shmget requests for an amount of shared memory and returns an id for it
	// shmat generates the address for the given segment using the id but
	// when we add the address to our tracker we need to know the size.
	// Memory tracker seems like a good place to keep the requests

	shmRequests []*shmRequest
}

func newTracker() *memoryTracker {
	return &memoryTracker{
		allocations: make(map[*prog.Call][]*allocation),
		mappings:    make([]*virtualMapping, 0),
	}
}

func (m *memoryTracker) findShmRequest(shmid uint64) *shmRequest {
	// Get the latest Request associated with id
	var ret *shmRequest
	for _, req := range m.shmRequests {
		r := req
		if req.shmid == shmid {
			ret = r
		}
	}
	return ret
}

func (m *memoryTracker) createMapping(call *prog.Call, callidx int, arg prog.Arg, start uint64, end uint64) {

	mapping := &virtualMapping{
		createdBy: call,
		callidx:   callidx,
		start:     start,
		end:       end,
		usedBy:    make([]*memDependency, 0),
	}
	mapping.usedBy = append(mapping.usedBy, &memDependency{start: start, end: end, arg: arg})
	m.mappings = append(m.mappings, mapping)
}

func (m *memoryTracker) findLatestOverlappingVMA(start uint64) *virtualMapping {
	var ret *virtualMapping
	for _, mapping := range m.mappings {
		mapCopy := mapping

		if mapping.start <= start && mapping.end >= start {
			ret = mapCopy
		}
	}
	return ret
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

	if err = m.fillOutMmaps(offset); err != nil {
		return
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

func (m *memoryTracker) fillOutMmaps(offset uint64) error {
	for _, mapping := range m.mappings {
		for _, dep := range mapping.usedBy {
			switch arg := dep.arg.(type) {
			case *prog.PointerArg:
				// Offset should align with the start of a mapping/end of previous mapping.
				arg.Address = offset + dep.start - mapping.start

				arg.Res = nil
				if arg.Address >= memAllocMaxMem || arg.Address+arg.VmaSize > memAllocMaxMem {
					return fmt.Errorf("Unable to allocate space for vma Call: %#v "+
						"Required memory is larger than what we allow."+
						"Offending address: %d. Skipping program generation for this prog...\n",
						mapping.getCall(), arg.Address)
				}
			default:
				log.Fatalf("Mapping needs to be Pointer Arg")
			}
		}
		offset += mapping.getEnd() - mapping.getStart()
	}
	return nil
}
