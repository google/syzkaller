// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
)

// Target describes target OS/arch pair.
type Target struct {
	OS         string
	Arch       string
	Revision   string // unique hash representing revision of the descriptions
	PtrSize    uint64
	PageSize   uint64
	NumPages   uint64
	DataOffset uint64

	Syscalls  []*Syscall
	Resources []*ResourceDesc
	Structs   []*KeyedStruct
	Consts    []ConstValue

	// MakeMmap creates call that maps [addr, addr+size) memory range.
	MakeMmap func(addr, size uint64) *Call

	// SanitizeCall neutralizes harmful calls.
	SanitizeCall func(c *Call)

	// AnnotateCall annotates a syscall invocation in C reproducers.
	// The returned string will be placed inside a comment except for the
	// empty string which will omit the comment.
	AnnotateCall func(c ExecCall) string

	// SpecialTypes allows target to do custom generation/mutation for some struct's and union's.
	// Map key is struct/union name for which custom generation/mutation is required.
	// Map value is custom generation/mutation function that will be called
	// for the corresponding type. g is helper object that allows generate random numbers,
	// allocate memory, etc. typ is the struct/union type. old is the old value of the struct/union
	// for mutation, or nil for generation. The function returns a new value of the struct/union,
	// and optionally any calls that need to be inserted before the arg reference.
	SpecialTypes map[string]func(g *Gen, typ Type, old Arg) (Arg, []*Call)

	// Special strings that can matter for the target.
	// Used as fallback when string type does not have own dictionary.
	StringDictionary []string

	// Resources that play auxiliary role, but widely used throughout all syscalls (e.g. pid/uid).
	AuxResources map[string]bool

	// Additional special invalid pointer values besides NULL to use.
	SpecialPointers []uint64

	// Filled by prog package:
	init        sync.Once
	initArch    func(target *Target)
	SyscallMap  map[string]*Syscall
	ConstMap    map[string]uint64
	resourceMap map[string]*ResourceDesc
	// Maps resource name to a list of calls that can create the resource.
	resourceCtors map[string][]*Syscall
	any           anyTypes
}

const maxSpecialPointers = 16

var targets = make(map[string]*Target)

func RegisterTarget(target *Target, initArch func(target *Target)) {
	key := target.OS + "/" + target.Arch
	if targets[key] != nil {
		panic(fmt.Sprintf("duplicate target %v", key))
	}
	target.initArch = initArch
	targets[key] = target
}

func GetTarget(OS, arch string) (*Target, error) {
	if OS == "android" {
		OS = "linux"
	}
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
	target.init.Do(target.lazyInit)
	return target, nil
}

func AllTargets() []*Target {
	var res []*Target
	for _, target := range targets {
		target.init.Do(target.lazyInit)
		res = append(res, target)
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].OS != res[j].OS {
			return res[i].OS < res[j].OS
		}
		return res[i].Arch < res[j].Arch
	})
	return res
}

func (target *Target) lazyInit() {
	target.SanitizeCall = func(c *Call) {}
	target.AnnotateCall = func(c ExecCall) string { return "" }
	target.initTarget()
	target.initArch(target)
	target.ConstMap = nil // currently used only by initArch
	// Give these 2 known addresses fixed positions and prepend target-specific ones at the end.
	target.SpecialPointers = append([]uint64{
		0x0000000000000000, // NULL pointer (keep this first because code uses special index=0 as NULL)
		0xffffffffffffffff, // unmapped kernel address (keep second because serialized value will match actual pointer value)
		0x9999999999999999, // non-canonical address
	}, target.SpecialPointers...)
	if len(target.SpecialPointers) > maxSpecialPointers {
		panic("too many special pointers")
	}
}

func (target *Target) initTarget() {
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}

	target.resourceMap = restoreLinks(target.Syscalls, target.Resources, target.Structs)
	target.Structs = nil

	target.SyscallMap = make(map[string]*Syscall)
	for i, c := range target.Syscalls {
		c.ID = i
		target.SyscallMap[c.Name] = c
		c.inputResources = target.getInputResources(c)
		c.outputResources = target.getOutputResources(c)
	}

	target.populateResourceCtors()
	target.resourceCtors = make(map[string][]*Syscall)
	for _, res := range target.Resources {
		target.resourceCtors[res.Name] = target.calcResourceCtors(res, false)
	}
	initAnyTypes(target)
}

func (target *Target) GetConst(name string) uint64 {
	if target.ConstMap == nil {
		panic("GetConst can only be used during target initialization")
	}
	v, ok := target.ConstMap[name]
	if !ok {
		panic(fmt.Sprintf("const %v is not defined for %v/%v", name, target.OS, target.Arch))
	}
	return v
}

func RestoreLinks(syscalls []*Syscall, resources []*ResourceDesc, structs []*KeyedStruct) {
	restoreLinks(syscalls, resources, structs)
}

func restoreLinks(syscalls []*Syscall, resources []*ResourceDesc, structs []*KeyedStruct) map[string]*ResourceDesc {
	resourceMap := make(map[string]*ResourceDesc)
	for _, res := range resources {
		resourceMap[res.Name] = res
	}
	keyedStructs := make(map[StructKey]*StructDesc)
	for _, desc := range structs {
		keyedStructs[desc.Key] = desc.Desc
	}
	for _, c := range syscalls {
		ForeachType(c, func(t0 Type) {
			switch t := t0.(type) {
			case *ResourceType:
				t.Desc = resourceMap[t.TypeName]
				if t.Desc == nil {
					panic("no resource desc")
				}
			case *StructType:
				t.StructDesc = keyedStructs[t.Key]
				if t.StructDesc == nil {
					panic("no struct desc")
				}
			case *UnionType:
				t.StructDesc = keyedStructs[t.Key]
				if t.StructDesc == nil {
					panic("no union desc")
				}
			}
		})
	}
	return resourceMap
}

type Gen struct {
	r *randGen
	s *state
}

func (g *Gen) Target() *Target {
	return g.r.target
}

func (g *Gen) Rand() *rand.Rand {
	return g.r.Rand
}

func (g *Gen) NOutOf(n, outOf int) bool {
	return g.r.nOutOf(n, outOf)
}

func (g *Gen) Alloc(ptrType Type, data Arg) (Arg, []*Call) {
	return g.r.allocAddr(g.s, ptrType, data.Size(), data), nil
}

func (g *Gen) GenerateArg(typ Type, pcalls *[]*Call) Arg {
	return g.generateArg(typ, pcalls, false)
}

func (g *Gen) GenerateSpecialArg(typ Type, pcalls *[]*Call) Arg {
	return g.generateArg(typ, pcalls, true)
}

func (g *Gen) generateArg(typ Type, pcalls *[]*Call, ignoreSpecial bool) Arg {
	arg, calls := g.r.generateArgImpl(g.s, typ, ignoreSpecial)
	*pcalls = append(*pcalls, calls...)
	g.r.target.assignSizesArray([]Arg{arg}, nil)
	return arg
}

func (g *Gen) MutateArg(arg0 Arg) (calls []*Call) {
	updateSizes := true
	for stop := false; !stop; stop = g.r.oneOf(3) {
		ma := &mutationArgs{target: g.r.target, ignoreSpecial: true}
		ForeachSubArg(arg0, ma.collectArg)
		if len(ma.args) == 0 {
			// TODO(dvyukov): probably need to return this condition
			// and updateSizes to caller so that Mutate can act accordingly.
			return
		}
		idx := g.r.Intn(len(ma.args))
		arg, ctx := ma.args[idx], ma.ctxes[idx]
		newCalls, ok := g.r.target.mutateArg(g.r, g.s, arg, ctx, &updateSizes)
		if !ok {
			continue
		}
		calls = append(calls, newCalls...)
	}
	return calls
}

type Builder struct {
	target *Target
	ma     *memAlloc
	p      *Prog
}

func MakeProgGen(target *Target) *Builder {
	return &Builder{
		target: target,
		ma:     newMemAlloc(target.NumPages * target.PageSize),
		p: &Prog{
			Target: target,
		},
	}
}

func (pg *Builder) Append(c *Call) error {
	pg.target.assignSizesCall(c)
	pg.target.SanitizeCall(c)
	pg.p.Calls = append(pg.p.Calls, c)
	return nil
}

func (pg *Builder) Allocate(size uint64) uint64 {
	return pg.ma.alloc(nil, size)
}

func (pg *Builder) AllocateVMA(npages uint64) uint64 {
	psize := pg.target.PageSize
	addr := pg.ma.alloc(nil, (npages+1)*psize)
	return (addr + psize - 1) & ^(psize - 1)
}

func (pg *Builder) Finalize() (*Prog, error) {
	if err := pg.p.validate(); err != nil {
		return nil, err
	}
	if _, err := pg.p.SerializeForExec(make([]byte, ExecBufferSize)); err != nil {
		return nil, err
	}
	p := pg.p
	pg.p = nil
	return p, nil
}
