// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"strings"

	"github.com/google/syzkaller/pkg/ifuzz"
)

type randGen struct {
	*rand.Rand
	target           *Target
	inCreateResource bool
	recDepth         map[string]int
}

func newRand(target *Target, rs rand.Source) *randGen {
	return &randGen{
		Rand:     rand.New(rs),
		target:   target,
		recDepth: make(map[string]int),
	}
}

func (r *randGen) rand(n int) uint64 {
	return uint64(r.Intn(n))
}

func (r *randGen) randRange(begin, end uint64) uint64 {
	return begin + uint64(r.Intn(int(end-begin+1)))
}

func (r *randGen) bin() bool {
	return r.Intn(2) == 0
}

func (r *randGen) oneOf(n int) bool {
	return r.Intn(n) == 0
}

func (r *randGen) rand64() uint64 {
	v := uint64(r.Int63())
	if r.bin() {
		v |= 1 << 63
	}
	return v
}

// Some potentially interesting integers.
var specialInts = []uint64{
	0, 1, 31, 32, 63, 64, 127, 128,
	129, 255, 256, 257, 511, 512,
	1023, 1024, 1025, 2047, 2048, 4095, 4096,
	(1 << 15) - 1, (1 << 15), (1 << 15) + 1,
	(1 << 16) - 1, (1 << 16), (1 << 16) + 1,
	(1 << 31) - 1, (1 << 31), (1 << 31) + 1,
	(1 << 32) - 1, (1 << 32), (1 << 32) + 1,
}

func (r *randGen) randInt() uint64 {
	v := r.rand64()
	switch {
	case r.nOutOf(100, 182):
		v %= 10
	case r.nOutOf(50, 82):
		v = specialInts[r.Intn(len(specialInts))]
	case r.nOutOf(10, 32):
		v %= 256
	case r.nOutOf(10, 22):
		v %= 4 << 10
	case r.nOutOf(10, 12):
		v %= 64 << 10
	default:
		v %= 1 << 31
	}
	switch {
	case r.nOutOf(100, 107):
	case r.nOutOf(5, 7):
		v = uint64(-int64(v))
	default:
		v <<= uint(r.Intn(63))
	}
	return v
}

func (r *randGen) randRangeInt(begin uint64, end uint64) uint64 {
	if r.oneOf(100) {
		return r.randInt()
	}
	return begin + (r.Uint64() % (end - begin + 1))
}

// biasedRand returns a random int in range [0..n),
// probability of n-1 is k times higher than probability of 0.
func (r *randGen) biasedRand(n, k int) int {
	nf, kf := float64(n), float64(k)
	rf := nf * (kf/2 + 1) * r.Float64()
	bf := (-1 + math.Sqrt(1+2*kf*rf/nf)) * nf / kf
	return int(bf)
}

func (r *randGen) randArrayLen() uint64 {
	const maxLen = 10
	// biasedRand produces: 10, 9, ..., 1, 0,
	// we want: 1, 2, ..., 9, 10, 0
	return uint64(maxLen-r.biasedRand(maxLen+1, 10)+1) % (maxLen + 1)
}

func (r *randGen) randBufLen() (n uint64) {
	switch {
	case r.nOutOf(50, 56):
		n = r.rand(256)
	case r.nOutOf(5, 6):
		n = 4 << 10
	}
	return
}

func (r *randGen) randPageCount() (n uint64) {
	switch {
	case r.nOutOf(100, 106):
		n = r.rand(4) + 1
	case r.nOutOf(5, 6):
		n = r.rand(20) + 1
	default:
		n = (r.rand(3) + 1) * 512
	}
	return
}

func (r *randGen) flags(vv []uint64) (v uint64) {
	switch {
	case r.nOutOf(90, 111):
		for stop := false; !stop; stop = r.bin() {
			v |= vv[r.rand(len(vv))]
		}
	case r.nOutOf(10, 21):
		v = vv[r.rand(len(vv))]
	case r.nOutOf(10, 11):
		v = 0
	default:
		v = r.rand64()
	}
	return
}

func (r *randGen) filename(s *state, typ *BufferType) string {
	fn := r.filenameImpl(s)
	if len(fn) != 0 && fn[len(fn)-1] == 0 {
		panic(fmt.Sprintf("zero-terminated filename: %q", fn))
	}
	if !typ.Varlen() {
		size := typ.Size()
		if uint64(len(fn)) < size {
			fn += string(make([]byte, size-uint64(len(fn))))
		}
		fn = fn[:size]
	} else if !typ.NoZ {
		fn += "\x00"
	}
	return fn
}

var specialFiles = []string{"", "/", "."}

func (r *randGen) filenameImpl(s *state) string {
	if r.oneOf(100) {
		return specialFiles[r.Intn(len(specialFiles))]
	}
	if len(s.files) == 0 || r.oneOf(10) {
		// Generate a new name.
		dir := "."
		if r.oneOf(2) && len(s.files) != 0 {
			files := make([]string, 0, len(s.files))
			for f := range s.files {
				files = append(files, f)
			}
			dir = files[r.Intn(len(files))]
			if len(dir) > 0 && dir[len(dir)-1] == 0 {
				dir = dir[:len(dir)-1]
			}
		}
		for i := 0; ; i++ {
			f := fmt.Sprintf("%v/file%v", dir, i)
			if !s.files[f] {
				return f
			}
		}
	}
	files := make([]string, 0, len(s.files))
	for f := range s.files {
		files = append(files, f)
	}
	return files[r.Intn(len(files))]
}

func (r *randGen) randString(s *state, t *BufferType) []byte {
	if len(t.Values) != 0 {
		return []byte(t.Values[r.Intn(len(t.Values))])
	}
	if len(s.strings) != 0 && r.bin() {
		// Return an existing string.
		// TODO(dvyukov): make s.strings indexed by string SubKind.
		strings := make([]string, 0, len(s.strings))
		for s := range s.strings {
			strings = append(strings, s)
		}
		return []byte(strings[r.Intn(len(strings))])
	}
	punct := []byte{'!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '\\',
		'/', ':', '.', ',', '-', '\'', '[', ']', '{', '}'}
	buf := new(bytes.Buffer)
	for r.nOutOf(3, 4) {
		switch {
		case r.nOutOf(10, 21):
			dict := r.target.StringDictionary
			if len(dict) != 0 {
				buf.WriteString(dict[r.Intn(len(dict))])
			}
		case r.nOutOf(10, 11):
			buf.Write([]byte{punct[r.Intn(len(punct))]})
		default:
			buf.Write([]byte{byte(r.Intn(256))})
		}
	}
	if r.oneOf(100) == t.NoZ {
		buf.Write([]byte{0})
	}
	return buf.Bytes()
}

func (r *randGen) allocAddr(s *state, typ Type, size uint64, data Arg) *PointerArg {
	return MakePointerArg(typ, s.ma.alloc(r, size), data)
}

func (r *randGen) allocVMA(s *state, typ Type, numPages uint64) *PointerArg {
	page := s.va.alloc(r, numPages)
	return MakeVmaPointerArg(typ, page*r.target.PageSize, numPages*r.target.PageSize)
}

func (r *randGen) createResource(s *state, res *ResourceType) (arg Arg, calls []*Call) {
	if r.inCreateResource {
		special := res.SpecialValues()
		return MakeResultArg(res, nil, special[r.Intn(len(special))]), nil
	}
	r.inCreateResource = true
	defer func() { r.inCreateResource = false }()

	kind := res.Desc.Name
	if r.oneOf(1000) {
		// Spoof resource subkind.
		var all []string
		for kind1 := range r.target.resourceMap {
			if r.target.isCompatibleResource(res.Desc.Kind[0], kind1) {
				all = append(all, kind1)
			}
		}
		kind = all[r.Intn(len(all))]
	}
	// Find calls that produce the necessary resources.
	metas0 := r.target.resourceCtors[kind]
	// TODO: reduce priority of less specialized ctors.
	var metas []*Syscall
	for _, meta := range metas0 {
		if s.ct == nil || s.ct.run[meta.ID] == nil {
			continue
		}
		metas = append(metas, meta)
	}
	if len(metas) == 0 {
		return MakeResultArg(res, nil, res.Default()), nil
	}

	// Now we have a set of candidate calls that can create the necessary resource.
	for i := 0; i < 1e3; i++ {
		// Generate one of them.
		meta := metas[r.Intn(len(metas))]
		calls := r.generateParticularCall(s, meta)
		s1 := newState(r.target, s.ct)
		s1.analyze(calls[len(calls)-1])
		// Now see if we have what we want.
		var allres []Arg
		for kind1, res1 := range s1.resources {
			if r.target.isCompatibleResource(kind, kind1) {
				allres = append(allres, res1...)
			}
		}
		if len(allres) != 0 {
			// Bingo!
			arg := MakeResultArg(res, allres[r.Intn(len(allres))], 0)
			return arg, calls
		}
		// Discard unsuccessful calls.
		// Note: s.ma/va have already noted allocations of the new objects
		// in discarded syscalls, ideally we should recreate state
		// by analyzing the program again.
		for _, c := range calls {
			ForeachArg(c, func(arg Arg, _ *ArgCtx) {
				if a, ok := arg.(*ResultArg); ok && a.Res != nil {
					delete(*a.Res.(ArgUsed).Used(), arg)
				}
			})
		}
	}
	// Generally we can loop several times, e.g. when we choose a call that returns
	// the resource in an array, but then generateArg generated that array of zero length.
	// But we must succeed eventually.
	var ctors []string
	for _, meta := range metas {
		ctors = append(ctors, meta.Name)
	}
	panic(fmt.Sprintf("failed to create a resource %v with %v",
		res.Desc.Kind[0], strings.Join(ctors, ", ")))
}

func (r *randGen) generateText(kind TextKind) []byte {
	switch kind {
	case Text_arm64:
		// Just a stub, need something better.
		text := make([]byte, 50)
		for i := range text {
			text[i] = byte(r.Intn(256))
		}
		return text
	default:
		cfg := createIfuzzConfig(kind)
		return ifuzz.Generate(cfg, r.Rand)
	}
}

func (r *randGen) mutateText(kind TextKind, text []byte) []byte {
	switch kind {
	case Text_arm64:
		return mutateData(r, text, 40, 60)
	default:
		cfg := createIfuzzConfig(kind)
		return ifuzz.Mutate(cfg, r.Rand, text)
	}
}

func createIfuzzConfig(kind TextKind) *ifuzz.Config {
	cfg := &ifuzz.Config{
		Len:  10,
		Priv: true,
		Exec: true,
		MemRegions: []ifuzz.MemRegion{
			{0 << 12, 1 << 12},
			{1 << 12, 1 << 12},
			{2 << 12, 1 << 12},
			{3 << 12, 1 << 12},
			{4 << 12, 1 << 12},
			{5 << 12, 1 << 12},
			{6 << 12, 1 << 12},
			{7 << 12, 1 << 12},
			{8 << 12, 1 << 12},
			{9 << 12, 1 << 12},
			{0xfec00000, 0x100}, // ioapic
		},
	}
	switch kind {
	case Text_x86_real:
		cfg.Mode = ifuzz.ModeReal16
	case Text_x86_16:
		cfg.Mode = ifuzz.ModeProt16
	case Text_x86_32:
		cfg.Mode = ifuzz.ModeProt32
	case Text_x86_64:
		cfg.Mode = ifuzz.ModeLong64
	}
	return cfg
}

// nOutOf returns true n out of outOf times.
func (r *randGen) nOutOf(n, outOf int) bool {
	if n <= 0 || n >= outOf {
		panic("bad probability")
	}
	v := r.Intn(outOf)
	return v < n
}

func (r *randGen) generateCall(s *state, p *Prog) []*Call {
	idx := 0
	if s.ct == nil {
		idx = r.Intn(len(r.target.Syscalls))
	} else {
		call := -1
		if len(p.Calls) != 0 {
			call = p.Calls[r.Intn(len(p.Calls))].Meta.ID
		}
		idx = s.ct.Choose(r.Rand, call)
	}
	meta := r.target.Syscalls[idx]
	return r.generateParticularCall(s, meta)
}

func (r *randGen) generateParticularCall(s *state, meta *Syscall) (calls []*Call) {
	c := &Call{
		Meta: meta,
		Ret:  MakeReturnArg(meta.Ret),
	}
	c.Args, calls = r.generateArgs(s, meta.Args)
	r.target.assignSizesCall(c)
	calls = append(calls, c)
	for _, c1 := range calls {
		r.target.SanitizeCall(c1)
	}
	return calls
}

// GenerateAllSyzProg generates a program that contains all pseudo syz_ calls for testing.
func (target *Target) GenerateAllSyzProg(rs rand.Source) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, nil)
	handled := make(map[string]bool)
	for _, meta := range target.Syscalls {
		if !strings.HasPrefix(meta.CallName, "syz_") || handled[meta.CallName] {
			continue
		}
		handled[meta.CallName] = true
		calls := r.generateParticularCall(s, meta)
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	if err := p.validate(); err != nil {
		panic(err)
	}
	return p
}

// GenerateSimpleProg generates the simplest non-empty program for testing
// (e.g. containing a single mmap).
func (target *Target) GenerateSimpleProg() *Prog {
	return &Prog{
		Target: target,
		Calls:  []*Call{target.MakeMmap(0, target.PageSize)},
	}
}

func (target *Target) GenerateUberMmapProg() *Prog {
	return &Prog{
		Target: target,
		Calls:  []*Call{target.MakeMmap(0, target.NumPages*target.PageSize)},
	}
}

func (r *randGen) generateArgs(s *state, types []Type) ([]Arg, []*Call) {
	var calls []*Call
	args := make([]Arg, len(types))

	// Generate all args. Size args have the default value 0 for now.
	for i, typ := range types {
		arg, calls1 := r.generateArg(s, typ)
		if arg == nil {
			panic(fmt.Sprintf("generated arg is nil for type '%v', types: %+v", typ.Name(), types))
		}
		args[i] = arg
		calls = append(calls, calls1...)
	}

	return args, calls
}

func (r *randGen) generateArg(s *state, typ Type) (arg Arg, calls []*Call) {
	return r.generateArgImpl(s, typ, false)
}

func (r *randGen) generateArgImpl(s *state, typ Type, ignoreSpecial bool) (arg Arg, calls []*Call) {
	if typ.Dir() == DirOut {
		// No need to generate something interesting for output scalar arguments.
		// But we still need to generate the argument itself so that it can be referenced
		// in subsequent calls. For the same reason we do generate pointer/array/struct
		// output arguments (their elements can be referenced in subsequent calls).
		switch typ.(type) {
		case *IntType, *FlagsType, *ConstType, *ProcType,
			*VmaType, *ResourceType:
			return r.target.defaultArg(typ), nil
		}
	}

	if typ.Optional() && r.oneOf(5) {
		return r.target.defaultArg(typ), nil
	}

	// Allow infinite recursion for optional pointers.
	if pt, ok := typ.(*PtrType); ok && typ.Optional() {
		switch pt.Type.(type) {
		case *StructType, *ArrayType, *UnionType:
			name := pt.Type.Name()
			r.recDepth[name]++
			defer func() {
				r.recDepth[name]--
				if r.recDepth[name] == 0 {
					delete(r.recDepth, name)
				}
			}()
			if r.recDepth[name] >= 3 {
				return MakeNullPointerArg(typ), nil
			}
		}
	}

	switch a := typ.(type) {
	case *ResourceType:
		switch {
		case r.nOutOf(1000, 1011):
			// Get an existing resource.
			var allres []Arg
			for name1, res1 := range s.resources {
				if name1 == "iocbptr" {
					continue
				}
				if r.target.isCompatibleResource(a.Desc.Name, name1) ||
					r.oneOf(20) && r.target.isCompatibleResource(a.Desc.Kind[0], name1) {
					allres = append(allres, res1...)
				}
			}
			if len(allres) != 0 {
				arg = MakeResultArg(a, allres[r.Intn(len(allres))], 0)
			} else {
				arg, calls = r.createResource(s, a)
			}
		case r.nOutOf(10, 11):
			// Create a new resource.
			arg, calls = r.createResource(s, a)
		default:
			special := a.SpecialValues()
			arg = MakeResultArg(a, nil, special[r.Intn(len(special))])
		}
		return arg, calls
	case *BufferType:
		switch a.Kind {
		case BufferBlobRand, BufferBlobRange:
			sz := r.randBufLen()
			if a.Kind == BufferBlobRange {
				sz = r.randRange(a.RangeBegin, a.RangeEnd)
			}
			if a.Dir() == DirOut {
				return MakeOutDataArg(a, sz), nil
			}
			data := make([]byte, sz)
			for i := range data {
				data[i] = byte(r.Intn(256))
			}
			return MakeDataArg(a, data), nil
		case BufferString:
			data := r.randString(s, a)
			if a.Dir() == DirOut {
				return MakeOutDataArg(a, uint64(len(data))), nil
			}
			return MakeDataArg(a, data), nil
		case BufferFilename:
			if a.Dir() == DirOut {
				var sz uint64
				switch {
				case !a.Varlen():
					sz = a.Size()
				case r.nOutOf(1, 3):
					sz = r.rand(100)
				case r.nOutOf(1, 2):
					sz = 108 // UNIX_PATH_MAX
				default:
					sz = 4096 // PATH_MAX
				}
				return MakeOutDataArg(a, sz), nil
			}
			return MakeDataArg(a, []byte(r.filename(s, a))), nil
		case BufferText:
			if a.Dir() == DirOut {
				return MakeOutDataArg(a, uint64(r.Intn(100))), nil
			}
			return MakeDataArg(a, r.generateText(a.Text)), nil
		default:
			panic("unknown buffer kind")
		}
	case *VmaType:
		npages := r.randPageCount()
		if a.RangeBegin != 0 || a.RangeEnd != 0 {
			npages = a.RangeBegin + uint64(r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
		}
		arg := r.allocVMA(s, a, npages)
		return arg, nil
	case *FlagsType:
		return MakeConstArg(a, r.flags(a.Vals)), nil
	case *ConstType:
		return MakeConstArg(a, a.Val), nil
	case *IntType:
		v := r.randInt()
		switch a.Kind {
		case IntFileoff:
			switch {
			case r.nOutOf(90, 101):
				v = 0
			case r.nOutOf(10, 11):
				v = r.rand(100)
			default:
				v = r.randInt()
			}
		case IntRange:
			v = r.randRangeInt(a.RangeBegin, a.RangeEnd)
		}
		return MakeConstArg(a, v), nil
	case *ProcType:
		return MakeConstArg(a, r.rand(int(a.ValuesPerProc))), nil
	case *ArrayType:
		var count uint64
		switch a.Kind {
		case ArrayRandLen:
			count = r.randArrayLen()
		case ArrayRangeLen:
			count = r.randRange(a.RangeBegin, a.RangeEnd)
		}
		var inner []Arg
		var calls []*Call
		for i := uint64(0); i < count; i++ {
			arg1, calls1 := r.generateArg(s, a.Type)
			inner = append(inner, arg1)
			calls = append(calls, calls1...)
		}
		return MakeGroupArg(a, inner), calls
	case *StructType:
		if !ignoreSpecial {
			if gen := r.target.SpecialTypes[a.Name()]; gen != nil && a.Dir() != DirOut {
				arg, calls = gen(&Gen{r, s}, a, nil)
				return
			}
		}
		args, calls := r.generateArgs(s, a.Fields)
		group := MakeGroupArg(a, args)
		return group, calls
	case *UnionType:
		if !ignoreSpecial {
			if gen := r.target.SpecialTypes[a.Name()]; gen != nil && a.Dir() != DirOut {
				arg, calls = gen(&Gen{r, s}, a, nil)
				return
			}
		}
		optType := a.Fields[r.Intn(len(a.Fields))]
		opt, calls := r.generateArg(s, optType)
		return MakeUnionArg(a, opt), calls
	case *PtrType:
		inner, calls := r.generateArg(s, a.Type)
		// TODO(dvyukov): remove knowledge about iocb from prog.
		if a.Type.Name() == "iocb" && len(s.resources["iocbptr"]) != 0 {
			// It is weird, but these are actually identified by kernel by address.
			// So try to reuse a previously used address.
			addrs := s.resources["iocbptr"]
			addr := addrs[r.Intn(len(addrs))].(*PointerArg)
			arg = MakePointerArg(a, addr.Address, inner)
			return arg, calls
		}
		arg := r.allocAddr(s, a, inner.Size(), inner)
		return arg, calls
	case *LenType:
		// Return placeholder value of 0 while generating len arg.
		return MakeConstArg(a, 0), nil
	case *CsumType:
		return MakeConstArg(a, 0), nil
	default:
		panic("unknown argument type")
	}
}
