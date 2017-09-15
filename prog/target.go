// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"sort"
)

// Target describes target OS/arch pair.
type Target struct {
	OS         string
	Arch       string
	Revision   string // unique hash representing revision of the descriptions
	PtrSize    uint64
	PageSize   uint64
	DataOffset uint64

	Syscalls  []*Syscall
	Resources []*ResourceDesc

	// Syscall used by MakeMmap.
	// It has some special meaning because there are usually too many of them.
	MmapSyscall *Syscall

	// MakeMmap creates call that maps [start, start+npages) page range.
	MakeMmap func(start, npages uint64) *Call

	// AnalyzeMmap analyzes the call c regarding mapping/unmapping memory.
	// If it maps/unmaps any memory returns [start, start+npages) range,
	// otherwise returns npages = 0.
	AnalyzeMmap func(c *Call) (start, npages uint64, mapped bool)

	// SanitizeCall neutralizes harmful calls.
	SanitizeCall func(c *Call)

	// SpecialStructs allows target to do custom generation/mutation for some struct types.
	// Map key is struct name for which custom generation/mutation is required.
	// Map value is custom generation/mutation function that will be called
	// for the corresponding structs. g is helper object that allows generate random numbers,
	// allocate memory, etc. typ is the struct type. old is the old value of the struct
	// for mutation, or nil for generation. The function returns a new value of the struct,
	// and optionally any calls that need to be inserted before the arg reference.
	SpecialStructs map[string]func(g *Gen, typ *StructType, old *GroupArg) (Arg, []*Call)

	// Special strings that can matter for the target.
	// Used as fallback when string type does not have own dictionary.
	StringDictionary []string

	// Filled by prog package:
	SyscallMap  map[string]*Syscall
	resourceMap map[string]*ResourceDesc
	// Maps resource name to a list of calls that can create the resource.
	resourceCtors map[string][]*Syscall
}

var targets = make(map[string]*Target)

func RegisterTarget(target *Target) {
	key := target.OS + "/" + target.Arch
	if targets[key] != nil {
		panic(fmt.Sprintf("duplicate target %v", key))
	}
	initTarget(target)
	targets[key] = target
}

func GetTarget(OS, arch string) (*Target, error) {
	key := OS + "/" + arch
	target := targets[key]
	if target == nil {
		var supported []string
		for _, t := range targets {
			supported = append(supported, fmt.Sprintf("%v/%v", t.OS, t.Arch))
		}
		sort.Strings(supported)
		return nil, fmt.Errorf("unknown target: %v (supported: %v)", key, supported)
	}
	return target, nil
}

func AllTargets() []*Target {
	var res []*Target
	for _, t := range targets {
		res = append(res, t)
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].OS != res[j].OS {
			return res[i].OS < res[j].OS
		}
		return res[i].Arch < res[j].Arch
	})
	return res
}

func initTarget(target *Target) {
	target.SyscallMap = make(map[string]*Syscall)
	for _, c := range target.Syscalls {
		target.SyscallMap[c.Name] = c
	}
	target.resourceMap = make(map[string]*ResourceDesc)
	target.resourceCtors = make(map[string][]*Syscall)
	for _, r := range target.Resources {
		target.resourceMap[r.Name] = r
		target.resourceCtors[r.Name] = target.calcResourceCtors(r.Kind, false)
	}
}

type Gen struct {
	r *randGen
	s *state
}

func (g *Gen) NOutOf(n, outOf int) bool {
	return g.r.nOutOf(n, outOf)
}

func (g *Gen) Alloc(ptrType Type, data Arg) (Arg, []*Call) {
	return g.r.addr(g.s, ptrType, data.Size(), data)
}
