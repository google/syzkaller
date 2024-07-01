// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/hash"
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
	BigEndian  bool

	Syscalls  []*Syscall
	Resources []*ResourceDesc
	Consts    []ConstValue
	Flags     []FlagDesc

	// MakeDataMmap creates calls that mmaps target data memory range.
	MakeDataMmap func() []*Call

	// Neutralize neutralizes harmful calls by transforming them into non-harmful ones
	// (e.g. an ioctl that turns off console output is turned into ioctl that turns on output).
	// fixStructure determines whether it's allowed to make structural changes (e.g. add or
	// remove arguments). It is helpful e.g. when we do neutralization while iterating over the
	// arguments.
	Neutralize func(c *Call, fixStructure bool) error

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
	SpecialTypes map[string]func(g *Gen, typ Type, dir Dir, old Arg) (Arg, []*Call)

	// Resources that play auxiliary role, but widely used throughout all syscalls (e.g. pid/uid).
	AuxResources map[string]bool

	// Additional special invalid pointer values besides NULL to use.
	SpecialPointers []uint64

	// Special file name length that can provoke bugs (e.g. PATH_MAX).
	SpecialFileLenghts []int

	// Filled by prog package:
	SyscallMap map[string]*Syscall
	ConstMap   map[string]uint64
	FlagsMap   map[string][]string

	init        sync.Once
	initArch    func(target *Target)
	types       []Type
	resourceMap map[string]*ResourceDesc
	// Maps resource name to a list of calls that can create the resource.
	resourceCtors map[string][]ResourceCtor
	any           anyTypes

	// The default ChoiceTable is used only by tests and utilities, so we initialize it lazily.
	defaultOnce        sync.Once
	defaultChoiceTable *ChoiceTable

	hintAttemptsMu sync.Mutex
	hintAttempts   map[uint64]int
}

const maxSpecialPointers = 16

var targets = make(map[string]*Target)

func RegisterTarget(target *Target, types []Type, initArch func(target *Target)) {
	key := target.OS + "/" + target.Arch
	if targets[key] != nil {
		panic(fmt.Sprintf("duplicate target %v", key))
	}
	target.initArch = initArch
	target.types = types
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
	target.Neutralize = func(c *Call, fixStructure bool) error { return nil }
	target.AnnotateCall = func(c ExecCall) string { return "" }
	target.initTarget()
	target.initUselessHints()
	target.initRelatedFields()
	target.initArch(target)
	// Give these 2 known addresses fixed positions and prepend target-specific ones at the end.
	target.SpecialPointers = append([]uint64{
		0x0000000000000000, // NULL pointer (keep this first because code uses special index=0 as NULL)
		0xffffffffffffffff, // unmapped kernel address (keep second because serialized value will match actual pointer value)
		0x9999999999999999, // non-canonical address
	}, target.SpecialPointers...)
	if len(target.SpecialPointers) > maxSpecialPointers {
		panic("too many special pointers")
	}
	if len(target.SpecialFileLenghts) == 0 {
		// Just some common lengths that can be used as PATH_MAX/MAX_NAME.
		target.SpecialFileLenghts = []int{256, 512, 4096}
	}
	for _, ln := range target.SpecialFileLenghts {
		if ln <= 0 || ln >= memAllocMaxMem {
			panic(fmt.Sprintf("bad special file length %v", ln))
		}
	}
	// These are used only during lazyInit.
	target.types = nil
}

func (target *Target) initTarget() {
	checkMaxCallID(len(target.Syscalls) - 1)
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}

	target.resourceMap = restoreLinks(target.Syscalls, target.Resources, target.types)
	target.initAnyTypes()

	target.SyscallMap = make(map[string]*Syscall)
	for i, c := range target.Syscalls {
		c.ID = i
		target.SyscallMap[c.Name] = c
	}

	target.FlagsMap = make(map[string][]string)
	for _, c := range target.Flags {
		target.FlagsMap[c.Name] = c.Values
	}

	target.populateResourceCtors()
	target.resourceCtors = make(map[string][]ResourceCtor)
	for _, res := range target.Resources {
		target.resourceCtors[res.Name] = target.calcResourceCtors(res, false)
	}

	target.hintAttempts = make(map[uint64]int)
}

func (target *Target) initUselessHints() {
	// Pre-compute useless hints for each type and deduplicate resulting maps
	// (there will be lots of duplicates).
	computed := make(map[Type]bool)
	dedup := make(map[string]map[uint64]struct{})
	ForeachType(target.Syscalls, func(t Type, ctx *TypeCtx) {
		hinter, ok := t.(uselessHinter)
		if !ok || computed[t] {
			return
		}
		computed[t] = true
		hints := hinter.calcUselessHints()
		if len(hints) == 0 {
			return
		}
		slices.Sort(hints)
		hints = slices.Compact(hints)
		sig := hash.String(hints)
		m := dedup[sig]
		if m == nil {
			m = make(map[uint64]struct{})
			for _, v := range hints {
				m[v] = struct{}{}
			}
			dedup[sig] = m
		}
		hinter.setUselessHints(m)
	})
}

func (target *Target) initRelatedFields() {
	// Compute sets of related fields that are used to reduce amount of produced hint replacements.
	// Related fields are sets of arguments to the same syscall, in the same position, that operate
	// on the same resource. The best example of related fields is a set of ioctl commands on the same fd:
	//
	//	ioctl$FOO1(fd fd_foo, cmd const[FOO1], ...)
	//	ioctl$FOO2(fd fd_foo, cmd const[FOO2], ...)
	//	ioctl$FOO3(fd fd_foo, cmd const[FOO3], ...)
	//
	// All cmd args related and we should not try to replace them with each other
	// (e.g. try to morph ioctl$FOO1 into ioctl$FOO2). This is both unnecessary, leads to confusing reproducers,
	// and in some cases to badly confused argument types, see e.g.:
	// https://github.com/google/syzkaller/issues/502
	// https://github.com/google/syzkaller/issues/4939
	//
	// However, notion of related fields is wider and includes e.g. socket syscall family/type/proto,
	// setsockopt consts, and in some cases even openat flags/mode.
	//
	// Related fields can include const, flags and int types.
	//
	// Notion of "same resource" is also quite generic b/c syscalls can accept several resource types,
	// and filenames/strings are also considered as a resource in this context. For example, openat syscalls
	// that operate on the same file are related, but are not related to openat calls that operate on other files.
	groups := make(map[string]map[Type]struct{})
	for _, call := range target.Syscalls {
		// Id is used to identify related syscalls.
		// We first collect all resources/strings/files. This needs to be done first b/c e.g. mmap has
		// fd resource at the end, so we need to do this before the next loop.
		id := call.CallName
		for i, field := range call.Args {
			switch arg := field.Type.(type) {
			case *ResourceType:
				id += fmt.Sprintf("-%v:%v", i, arg.Name())
			case *PtrType:
				if typ, ok := arg.Elem.(*BufferType); ok && typ.Kind == BufferString && len(typ.Values) == 1 {
					id += fmt.Sprintf("-%v:%v", i, typ.Values[0])
				}
			}
		}
		// Now we group const/flags args together.
		// But also if we see a const, we update id to include it. This is required for e.g.
		// socket/socketpair/setsockopt calls. For these calls all families can be groups, but types should be
		// grouped only for the same family, and protocols should be grouped only for the same family+type.
		// We assume the "more important" discriminating arguments come first (this is not necessary true,
		// but seems to be the case in real syscalls as it's unreasonable to pass less important things first).
		for i, field := range call.Args {
			switch field.Type.(type) {
			case *ConstType:
			case *FlagsType:
			case *IntType:
			default:
				continue
			}
			argID := fmt.Sprintf("%v/%v", id, i)
			group := groups[argID]
			if group == nil {
				group = make(map[Type]struct{})
				groups[argID] = group
			}
			call.Args[i].relatedFields = group
			group[field.Type] = struct{}{}
			switch arg := field.Type.(type) {
			case *ConstType:
				id += fmt.Sprintf("-%v:%v", i, arg.Val)
			}
		}
	}
	// Drop groups that consist of only a single field as they are not useful.
	for _, call := range target.Syscalls {
		for i := range call.Args {
			if len(call.Args[i].relatedFields) == 1 {
				call.Args[i].relatedFields = nil
			}
		}
	}
}

func (target *Target) GetConst(name string) uint64 {
	v, ok := target.ConstMap[name]
	if !ok {
		panic(fmt.Sprintf("const %v is not defined for %v/%v", name, target.OS, target.Arch))
	}
	return v
}

func (target *Target) sanitize(c *Call, fix bool) error {
	// For now, even though we accept the fix argument, it does not have the full effect.
	// It de facto only denies structural changes, e.g. deletions of arguments.
	// TODO: rewrite the corresponding sys/*/init.go code.
	return target.Neutralize(c, fix)
}

func RestoreLinks(syscalls []*Syscall, resources []*ResourceDesc, types []Type) {
	restoreLinks(syscalls, resources, types)
}

var (
	typeRefMu sync.Mutex
	typeRefs  atomic.Value // []Type
)

func restoreLinks(syscalls []*Syscall, resources []*ResourceDesc, types []Type) map[string]*ResourceDesc {
	typeRefMu.Lock()
	defer typeRefMu.Unlock()
	refs := []Type{nil}
	if old := typeRefs.Load(); old != nil {
		refs = old.([]Type)
	}
	for _, typ := range types {
		typ.setRef(Ref(len(refs)))
		refs = append(refs, typ)
	}
	typeRefs.Store(refs)

	resourceMap := make(map[string]*ResourceDesc)
	for _, res := range resources {
		resourceMap[res.Name] = res
	}

	ForeachType(syscalls, func(typ Type, ctx *TypeCtx) {
		if ref, ok := typ.(Ref); ok {
			typ = types[ref]
			*ctx.Ptr = typ
		}
		switch t := typ.(type) {
		case *ResourceType:
			t.Desc = resourceMap[t.TypeName]
			if t.Desc == nil {
				panic("no resource desc")
			}
		}
	})
	return resourceMap
}

func (target *Target) DefaultChoiceTable() *ChoiceTable {
	target.defaultOnce.Do(func() {
		target.defaultChoiceTable = target.BuildChoiceTable(nil, nil)
	})
	return target.defaultChoiceTable
}

func (target *Target) RequiredGlobs() []string {
	globs := make(map[string]bool)
	ForeachType(target.Syscalls, func(typ Type, ctx *TypeCtx) {
		switch a := typ.(type) {
		case *BufferType:
			if a.Kind == BufferGlob {
				for _, glob := range requiredGlobs(a.SubKind) {
					globs[glob] = true
				}
			}
		}
	})
	return stringMapToSlice(globs)
}

func (target *Target) UpdateGlobs(globFiles map[string][]string) {
	// TODO: make host.DetectSupportedSyscalls below filter out globs with no values.
	// Also make prog package more strict with respect to generation/mutation of globs
	// with no values (they still can appear in tests and tools). We probably should
	// generate an empty string for these and never mutate.
	ForeachType(target.Syscalls, func(typ Type, ctx *TypeCtx) {
		switch a := typ.(type) {
		case *BufferType:
			if a.Kind == BufferGlob {
				a.Values = populateGlob(a.SubKind, globFiles)
			}
		}
	})
}

func requiredGlobs(pattern string) []string {
	var res []string
	for _, tok := range strings.Split(pattern, ":") {
		if tok[0] != '-' {
			res = append(res, tok)
		}
	}
	return res
}

func populateGlob(pattern string, globFiles map[string][]string) []string {
	files := make(map[string]bool)
	parts := strings.Split(pattern, ":")
	for _, tok := range parts {
		if tok[0] != '-' {
			for _, file := range globFiles[tok] {
				files[file] = true
			}
		}
	}
	for _, tok := range parts {
		if tok[0] == '-' {
			delete(files, tok[1:])
		}
	}
	return stringMapToSlice(files)
}

func stringMapToSlice(m map[string]bool) []string {
	var res []string
	for k := range m {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
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

func (g *Gen) Alloc(ptrType Type, dir Dir, data Arg) (Arg, []*Call) {
	return g.r.allocAddr(g.s, ptrType, dir, data.Size(), data), nil
}

func (g *Gen) GenerateArg(typ Type, dir Dir, pcalls *[]*Call) Arg {
	return g.generateArg(typ, dir, pcalls, false)
}

func (g *Gen) GenerateSpecialArg(typ Type, dir Dir, pcalls *[]*Call) Arg {
	return g.generateArg(typ, dir, pcalls, true)
}

func (g *Gen) generateArg(typ Type, dir Dir, pcalls *[]*Call, ignoreSpecial bool) Arg {
	arg, calls := g.r.generateArgImpl(g.s, typ, dir, ignoreSpecial)
	*pcalls = append(*pcalls, calls...)
	g.r.target.assignSizesArray([]Arg{arg}, []Field{{Name: "", Type: arg.Type()}}, nil)
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
		arg, ctx := ma.chooseArg(g.r.Rand)
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
	pg.target.sanitize(c, true)
	pg.p.Calls = append(pg.p.Calls, c)
	return nil
}

func (pg *Builder) Allocate(size, alignment uint64) uint64 {
	return pg.ma.alloc(nil, size, alignment)
}

func (pg *Builder) AllocateVMA(npages uint64) uint64 {
	return pg.ma.alloc(nil, npages*pg.target.PageSize, pg.target.PageSize)
}

func (pg *Builder) Finalize() (*Prog, error) {
	if err := pg.p.validate(); err != nil {
		return nil, err
	}
	if _, err := pg.p.SerializeForExec(); err != nil {
		return nil, err
	}
	p := pg.p
	pg.p = nil
	return p, nil
}
