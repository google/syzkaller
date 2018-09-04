package trace2syz

import (
	"fmt"
	"github.com/google/syzkaller/prog"
)

const (
	memAllocMaxMem = 16 << 20
)

type allocation struct {
	numBytes uint64
	arg      prog.Arg
}

/*
Memory dependency represents the dependency of a call on a
virtual memory mapping. We assume the dependency is contiguous
as we will allocate pointers for arguments in a separate mmap at the
beginning of the function. Moreover there are no calls which we know of
that take a list of pages as arguments.
*/
type MemDependency struct {
	Callidx int
	arg     prog.Arg
	start   uint64
	end     uint64
}

func newMemDependency(callidx int, usedBy prog.Arg, start uint64, end uint64) *MemDependency {
	return &MemDependency{
		Callidx: callidx,
		arg:     usedBy,
		start:   start,
		end:     end,
	}
}

type VirtualMapping struct {
	usedBy    []*MemDependency
	createdBy *prog.Call
	callidx   int
	start     uint64
	end       uint64
}

type ShmRequest struct {
	size  uint64
	shmid uint64
}

func (s *ShmRequest) getSize() uint64 {
	return s.size
}

func (vm *VirtualMapping) getUsedBy() []*MemDependency {
	return vm.usedBy
}

func (vm *VirtualMapping) addDependency(md *MemDependency) {
	vm.usedBy = append(vm.usedBy, md)
}

func (vm *VirtualMapping) getEnd() uint64 {
	return vm.end
}

func (vm *VirtualMapping) getStart() uint64 {
	return vm.start
}

func (vm *VirtualMapping) getCall() *prog.Call {
	return vm.createdBy
}

func (vm *VirtualMapping) getCallIdx() int {
	return vm.callidx
}

type MemoryTracker struct {
	allocations map[*prog.Call][]*allocation
	mappings    []*VirtualMapping
	/*
	 We keep the SYSTEM V shared mapping requests because
	 the creation of memory is broken into two steps: shmget, shmat
	 shmget requests for an amount of shared memory and returns an id for it
	 shmat generates the address for the given segment using the id but
	 when we add the address to our tracker we need to know the size.
	 Memory tracker seems like a good place to keep the requests
	*/
	shmRequests []*ShmRequest
}

func newTracker() *MemoryTracker {
	m := new(MemoryTracker)
	m.allocations = make(map[*prog.Call][]*allocation)
	m.mappings = make([]*VirtualMapping, 0)
	return m
}

func (m *MemoryTracker) addShmRequest(shmid uint64, size uint64) {
	shmRequest := &ShmRequest{
		size:  size,
		shmid: shmid,
	}
	m.shmRequests = append(m.shmRequests, shmRequest)
}

func (m *MemoryTracker) findShmRequest(shmid uint64) *ShmRequest {
	//Get the latest Request associated with id
	var ret *ShmRequest
	for _, req := range m.shmRequests {
		r := req
		if req.shmid == shmid {
			ret = r
		}
	}
	return ret
}

func (m *MemoryTracker) createMapping(call *prog.Call, callidx int, arg prog.Arg, start uint64, end uint64) {

	mapping := &VirtualMapping{
		createdBy: call,
		callidx:   callidx,
		start:     start,
		end:       end,
		usedBy:    make([]*MemDependency, 0),
	}
	mapping.usedBy = append(mapping.usedBy, &MemDependency{start: start, end: end, arg: arg})
	m.mappings = append(m.mappings, mapping)
}

func (m *MemoryTracker) findLatestOverlappingVMA(start uint64) *VirtualMapping {
	var ret *VirtualMapping
	for _, mapping := range m.mappings {
		mapCopy := mapping

		if mapping.start <= start && mapping.end >= start {
			ret = mapCopy
		}
	}
	return ret
}

func (m *MemoryTracker) addAllocation(call *prog.Call, size uint64, arg prog.Arg) {
	switch arg.(type) {
	case *prog.PointerArg:
	default:
		panic("Adding allocation for non pointer")
	}
	alloc := new(allocation)
	alloc.arg = arg
	alloc.numBytes = size
	if _, ok := m.allocations[call]; !ok {
		m.allocations[call] = make([]*allocation, 0)
	}
	m.allocations[call] = append(m.allocations[call], alloc)
}

func (m *MemoryTracker) fillOutMemory(prog *prog.Prog) (err error) {
	var offset uint64
	if offset, err = m.fillOutPtrArgs(prog); err != nil {
		return
	}

	if offset%PageSize > 0 {
		offset = (offset/PageSize + 1) * PageSize
	}

	if err = m.fillOutMmaps(offset); err != nil {
		return
	}
	return nil
}

func (m *MemoryTracker) fillOutPtrArgs(p *prog.Prog) (uint64, error) {
	offset := uint64(0)

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
						"in Call: %v. Required memory is larger than what is allowed by Syzkaller."+
						"Offending address: %d. Skipping seed generation for this prog...\n",
						arg, call, arg.Address)
				}
			default:
				panic("Pointer Arg Failed")
			}
		}
	}

	if offset%PageSize > 0 {
		offset = (offset/PageSize + 1) * PageSize
	}

	return offset, nil
}

func (m *MemoryTracker) fillOutMmaps(offset uint64) error {
	for _, mapping := range m.mappings {
		for _, dep := range mapping.usedBy {
			switch arg := dep.arg.(type) {
			case *prog.PointerArg:
				//Offset should align with the start of a mapping/end of previous mapping.
				arg.Address = offset + dep.start - mapping.start

				arg.Res = nil
				if arg.Address >= memAllocMaxMem || arg.Address+arg.VmaSize > memAllocMaxMem {
					return fmt.Errorf("Unable to allocate space for vma Call: %#v "+
						"Required memory is larger than what is allowed by Syzkaller."+
						"Offending address: %d. Skipping seed generation for this prog...\n",
						mapping.getCall(), arg.Address)
				}
			default:
				panic("Mapping needs to be Pointer Arg")
			}
		}
		offset += mapping.getEnd() - mapping.getStart()
	}
	return nil
}

//getTotalMemoryAllocations calculates the total amount of memory needed by all the arguments
//of every system call. Currently we are allocating memory in a naive fashion by providing
//a new memory region for every every argument. However, this can be significantly improved
func (m *MemoryTracker) getTotalMemoryAllocations(p *prog.Prog) uint64 {
	sum := uint64(0)
	for _, call := range p.Calls {
		if _, ok := m.allocations[call]; !ok {
			continue
		}
		for _, a := range m.allocations[call] {
			sum += a.numBytes
		}
	}
	if sum%PageSize > 0 {
		sum = (sum/PageSize + 1) * PageSize
	}
	return sum
}
