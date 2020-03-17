// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/ifuzz"
	_ "github.com/google/syzkaller/pkg/ifuzz/generated" // pull in generated instruction descriptions
)

const (
	// "Recommended" number of calls in programs that we try to aim at during fuzzing.
	RecommendedCalls = 20
	// "Recommended" max number of calls in programs.
	// If we receive longer programs from hub/corpus we discard them.
	MaxCalls = 40
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

var (
	// Some potentially interesting integers.
	specialInts = []uint64{
		0, 1, 31, 32, 63, 64, 127, 128,
		129, 255, 256, 257, 511, 512,
		1023, 1024, 1025, 2047, 2048, 4095, 4096,
		(1 << 15) - 1, (1 << 15), (1 << 15) + 1,
		(1 << 16) - 1, (1 << 16), (1 << 16) + 1,
		(1 << 31) - 1, (1 << 31), (1 << 31) + 1,
		(1 << 32) - 1, (1 << 32), (1 << 32) + 1,
	}
	// The indexes (exclusive) for the maximum specialInts values that fit in 1, 2, ... 8 bytes.
	specialIntIndex [9]int
)

func init() {
	sort.Slice(specialInts, func(i, j int) bool {
		return specialInts[i] < specialInts[j]
	})
	for i := range specialIntIndex {
		bitSize := uint64(8 * i)
		specialIntIndex[i] = sort.Search(len(specialInts), func(i int) bool {
			return specialInts[i]>>bitSize != 0
		})
	}
}

func (r *randGen) randInt64() uint64 {
	return r.randInt(64)
}

func (r *randGen) randInt(bits uint64) uint64 {
	v := r.rand64()
	switch {
	case r.nOutOf(100, 182):
		v %= 10
	case bits >= 8 && r.nOutOf(50, 82):
		v = specialInts[r.Intn(specialIntIndex[bits/8])]
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
		v <<= uint(r.Intn(int(bits)))
	}
	return truncateToBitSize(v, bits)
}

func truncateToBitSize(v, bitSize uint64) uint64 {
	if bitSize == 0 || bitSize > 64 {
		panic(fmt.Sprintf("invalid bitSize value: %d", bitSize))
	}
	return v & uint64(1<<bitSize-1)
}

func (r *randGen) randRangeInt(begin, end, bitSize, align uint64) uint64 {
	if r.oneOf(100) {
		return r.randInt(bitSize)
	}
	if align != 0 {
		if begin == 0 && int64(end) == -1 {
			// Special [0:-1] range for all possible values.
			end = uint64(1<<bitSize - 1)
		}
		endAlign := (end - begin) / align
		return begin + r.randRangeInt(0, endAlign, bitSize, 0)*align
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

// Change a flag value or generate a new one.
// If you are changing this function, run TestFlags and examine effect of results.
func (r *randGen) flags(vv []uint64, bitmask bool, oldVal uint64) uint64 {
	// Get these simpler cases out of the way first.
	// Once in a while we want to return completely random values,
	// or 0 which is frequently special.
	if r.oneOf(100) {
		return r.rand64()
	}
	if r.oneOf(50) {
		return 0
	}
	if !bitmask && oldVal != 0 && r.oneOf(100) {
		// Slightly increment/decrement the old value.
		// This is especially important during mutation when len(vv) == 1,
		// otherwise in that case we produce almost no randomness
		// (the value is always mutated to 0).
		inc := uint64(1)
		if r.bin() {
			inc = ^uint64(0)
		}
		v := oldVal + inc
		for r.bin() {
			v += inc
		}
		return v
	}
	if len(vv) == 1 {
		// This usually means that value or 0,
		// at least that's our best (and only) bet.
		if r.bin() {
			return 0
		}
		return vv[0]
	}
	if !bitmask && !r.oneOf(10) {
		// Enumeration, so just choose one of the values.
		return vv[r.rand(len(vv))]
	}
	if r.oneOf(len(vv) + 4) {
		return 0
	}
	// Flip rand bits. Do this for non-bitmask sometimes
	// because we may have detected bitmask incorrectly for complex cases
	// (e.g. part of the vlaue is bitmask and another is not).
	v := oldVal
	if v != 0 && r.oneOf(10) {
		v = 0 // Ignore the old value sometimes.
	}
	// We don't want to return 0 here, because we already given 0
	// fixed probability above (otherwise we get 0 too frequently).
	for v == 0 || r.nOutOf(2, 3) {
		flag := vv[r.rand(len(vv))]
		if r.oneOf(20) {
			// Try choosing adjacent bit values in case we forgot
			// to add all relevant flags to the descriptions.
			if r.bin() {
				flag >>= 1
			} else {
				flag <<= 1
			}
		}
		v ^= flag
	}
	return v
}

func (r *randGen) filename(s *state, typ *BufferType) string {
	fn := r.filenameImpl(s)
	if len(fn) != 0 && fn[len(fn)-1] == 0 {
		panic(fmt.Sprintf("zero-terminated filename: %q", fn))
	}
	if escapingFilename(fn) {
		panic(fmt.Sprintf("sandbox escaping file name %q, s.files are %v", fn, s.files))
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

func escapingFilename(file string) bool {
	file = filepath.Clean(file)
	return len(file) >= 1 && file[0] == '/' ||
		len(file) >= 2 && file[0] == '.' && file[1] == '.'
}

var specialFiles = []string{"", "."}

func (r *randGen) filenameImpl(s *state) string {
	if r.oneOf(100) {
		return specialFiles[r.Intn(len(specialFiles))]
	}
	if len(s.files) == 0 || r.oneOf(10) {
		// Generate a new name.
		dir := "."
		if r.oneOf(2) && len(s.files) != 0 {
			dir = r.randFromMap(s.files)
			if len(dir) > 0 && dir[len(dir)-1] == 0 {
				dir = dir[:len(dir)-1]
			}
			if r.oneOf(10) && filepath.Clean(dir)[0] != '.' {
				dir += "/.."
			}
		}
		for i := 0; ; i++ {
			f := fmt.Sprintf("%v/file%v", dir, i)
			if !s.files[f] {
				return f
			}
		}
	}
	return r.randFromMap(s.files)
}

func (r *randGen) randFromMap(m map[string]bool) string {
	files := make([]string, 0, len(m))
	for f := range m {
		files = append(files, f)
	}
	sort.Strings(files)
	return files[r.Intn(len(files))]
}

func (r *randGen) randString(s *state, t *BufferType) []byte {
	if len(t.Values) != 0 {
		return []byte(t.Values[r.Intn(len(t.Values))])
	}
	if len(s.strings) != 0 && r.bin() {
		// Return an existing string.
		// TODO(dvyukov): make s.strings indexed by string SubKind.
		return []byte(r.randFromMap(s.strings))
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
		return nil, nil
	}
	r.inCreateResource = true
	defer func() { r.inCreateResource = false }()

	kind := res.Desc.Name
	// We may have no resources, but still be in createResource due to ANYRES.
	if len(r.target.resourceMap) != 0 && r.oneOf(1000) {
		// Spoof resource subkind.
		var all []string
		for kind1 := range r.target.resourceMap {
			if r.target.isCompatibleResource(res.Desc.Kind[0], kind1) {
				all = append(all, kind1)
			}
		}
		if len(all) == 0 {
			panic(fmt.Sprintf("got no spoof resources for %v in %v/%v",
				kind, r.target.OS, r.target.Arch))
		}
		sort.Strings(all)
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
		return res.DefaultArg(), nil
	}

	// Now we have a set of candidate calls that can create the necessary resource.
	for i := 0; i < 1e3; i++ {
		// Generate one of them.
		meta := metas[r.Intn(len(metas))]
		calls := r.generateParticularCall(s, meta)
		s1 := newState(r.target, s.ct, nil)
		s1.analyze(calls[len(calls)-1])
		// Now see if we have what we want.
		var allres []*ResultArg
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
					delete(a.Res.uses, a)
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
	case TextTarget:
		if r.target.Arch == "amd64" || r.target.Arch == "386" {
			cfg := createTargetIfuzzConfig(r.target)
			return ifuzz.Generate(cfg, r.Rand)
		}
		fallthrough
	case TextArm64:
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
	case TextTarget:
		if r.target.Arch == "amd64" || r.target.Arch == "386" {
			cfg := createTargetIfuzzConfig(r.target)
			return ifuzz.Mutate(cfg, r.Rand, text)
		}
		fallthrough
	case TextArm64:
		return mutateData(r, text, 40, 60)
	default:
		cfg := createIfuzzConfig(kind)
		return ifuzz.Mutate(cfg, r.Rand, text)
	}
}

func createTargetIfuzzConfig(target *Target) *ifuzz.Config {
	cfg := &ifuzz.Config{
		Len:  10,
		Priv: false,
		Exec: true,
		MemRegions: []ifuzz.MemRegion{
			{Start: target.DataOffset, Size: target.NumPages * target.PageSize},
		},
	}
	for _, p := range target.SpecialPointers {
		cfg.MemRegions = append(cfg.MemRegions, ifuzz.MemRegion{
			Start: p & ^target.PageSize, Size: p & ^target.PageSize + target.PageSize,
		})
	}
	switch target.Arch {
	case "amd64":
		cfg.Mode = ifuzz.ModeLong64
	case "386":
		cfg.Mode = ifuzz.ModeProt32
	default:
		panic("unknown text kind")
	}
	return cfg

}

func createIfuzzConfig(kind TextKind) *ifuzz.Config {
	cfg := &ifuzz.Config{
		Len:  10,
		Priv: true,
		Exec: true,
		MemRegions: []ifuzz.MemRegion{
			{Start: 0 << 12, Size: 1 << 12},
			{Start: 1 << 12, Size: 1 << 12},
			{Start: 2 << 12, Size: 1 << 12},
			{Start: 3 << 12, Size: 1 << 12},
			{Start: 4 << 12, Size: 1 << 12},
			{Start: 5 << 12, Size: 1 << 12},
			{Start: 6 << 12, Size: 1 << 12},
			{Start: 7 << 12, Size: 1 << 12},
			{Start: 8 << 12, Size: 1 << 12},
			{Start: 9 << 12, Size: 1 << 12},
			{Start: 0xfec00000, Size: 0x100}, // ioapic
		},
	}
	switch kind {
	case TextX86Real:
		cfg.Mode = ifuzz.ModeReal16
	case TextX86bit16:
		cfg.Mode = ifuzz.ModeProt16
	case TextX86bit32:
		cfg.Mode = ifuzz.ModeProt32
	case TextX86bit64:
		cfg.Mode = ifuzz.ModeLong64
	default:
		panic("unknown text kind")
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

func (r *randGen) generateCall(s *state, p *Prog, insertionPoint int) []*Call {
	idx := 0
	if s.ct == nil {
		idx = r.Intn(len(r.target.Syscalls))
	} else if insertionPoint <= 0 {
		idx = s.ct.enabledCalls[r.Intn(len(s.ct.enabledCalls))].ID
	} else {
		call := -1
		if len(p.Calls) != 0 {
			// Choosing the base call is based on the insertion point of the new calls sequence.
			call = p.Calls[r.Intn(insertionPoint)].Meta.ID
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
	return append(calls, c)
}

// GenerateAllSyzProg generates a program that contains all pseudo syz_ calls for testing.
func (target *Target) GenerateAllSyzProg(rs rand.Source) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, nil, nil)
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
			return typ.DefaultArg(), nil
		}
	}

	if typ.Optional() && r.oneOf(5) {
		if res, ok := typ.(*ResourceType); ok {
			v := res.Desc.Values[r.Intn(len(res.Desc.Values))]
			return MakeResultArg(typ, nil, v), nil
		}
		return typ.DefaultArg(), nil
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
				return MakeSpecialPointerArg(typ, 0), nil
			}
		}
	}

	if !ignoreSpecial && typ.Dir() != DirOut {
		switch typ.(type) {
		case *StructType, *UnionType:
			if gen := r.target.SpecialTypes[typ.Name()]; gen != nil {
				return gen(&Gen{r, s}, typ, nil)
			}
		}
	}

	return typ.generate(r, s)
}

func (a *ResourceType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	if r.oneOf(3) {
		arg = r.existingResource(s, a)
		if arg != nil {
			return
		}
	}
	if r.nOutOf(2, 3) {
		arg, calls = r.resourceCentric(s, a)
		if arg != nil {
			return
		}
	}
	if r.nOutOf(4, 5) {
		arg, calls = r.createResource(s, a)
		if arg != nil {
			return
		}
	}
	special := a.SpecialValues()
	arg = MakeResultArg(a, nil, special[r.Intn(len(special))])
	return
}

func (a *BufferType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
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
}

func (a *VmaType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	npages := r.randPageCount()
	if a.RangeBegin != 0 || a.RangeEnd != 0 {
		npages = a.RangeBegin + uint64(r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
	}
	return r.allocVMA(s, a, npages), nil
}

func (a *FlagsType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	return MakeConstArg(a, r.flags(a.Vals, a.BitMask, 0)), nil
}

func (a *ConstType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	return MakeConstArg(a, a.Val), nil
}

func (a *IntType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	bits := a.TypeBitSize()
	v := r.randInt(bits)
	switch a.Kind {
	case IntRange:
		v = r.randRangeInt(a.RangeBegin, a.RangeEnd, bits, a.Align)
	}
	return MakeConstArg(a, v), nil
}

func (a *ProcType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	return MakeConstArg(a, r.rand(int(a.ValuesPerProc))), nil
}

func (a *ArrayType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	var count uint64
	switch a.Kind {
	case ArrayRandLen:
		count = r.randArrayLen()
	case ArrayRangeLen:
		count = r.randRange(a.RangeBegin, a.RangeEnd)
	}
	var inner []Arg
	for i := uint64(0); i < count; i++ {
		arg1, calls1 := r.generateArg(s, a.Type)
		inner = append(inner, arg1)
		calls = append(calls, calls1...)
	}
	return MakeGroupArg(a, inner), calls
}

func (a *StructType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	args, calls := r.generateArgs(s, a.Fields)
	group := MakeGroupArg(a, args)
	return group, calls
}

func (a *UnionType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	optType := a.Fields[r.Intn(len(a.Fields))]
	opt, calls := r.generateArg(s, optType)
	return MakeUnionArg(a, opt), calls
}

func (a *PtrType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	if r.oneOf(1000) {
		index := r.rand(len(r.target.SpecialPointers))
		return MakeSpecialPointerArg(a, index), nil
	}
	inner, calls := r.generateArg(s, a.Type)
	arg = r.allocAddr(s, a, inner.Size(), inner)
	return arg, calls
}

func (a *LenType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	// Updated later in assignSizesCall.
	return MakeConstArg(a, 0), nil
}

func (a *CsumType) generate(r *randGen, s *state) (arg Arg, calls []*Call) {
	// Filled at runtime by executor.
	return MakeConstArg(a, 0), nil
}

func (r *randGen) existingResource(s *state, res *ResourceType) Arg {
	alltypes := make([][]*ResultArg, 0, len(s.resources))
	for _, res1 := range s.resources {
		alltypes = append(alltypes, res1)
	}
	sort.Slice(alltypes, func(i, j int) bool {
		return alltypes[i][0].Type().Name() < alltypes[j][0].Type().Name()
	})
	var allres []*ResultArg
	for _, res1 := range alltypes {
		name1 := res1[0].Type().Name()
		if r.target.isCompatibleResource(res.Desc.Name, name1) ||
			r.oneOf(50) && r.target.isCompatibleResource(res.Desc.Kind[0], name1) {
			allres = append(allres, res1...)
		}
	}
	if len(allres) == 0 {
		return nil
	}
	return MakeResultArg(res, allres[r.Intn(len(allres))], 0)
}

// Finds a compatible resource with the type `t` and the calls that initialize that resource.
func (r *randGen) resourceCentric(s *state, t *ResourceType) (arg Arg, calls []*Call) {
	var p *Prog
	var resource *ResultArg
	for idx := range r.Perm(len(s.corpus)) {
		p = s.corpus[idx].Clone()
		resources := getCompatibleResources(p, t.TypeName, r)
		if len(resources) > 0 {
			resource = resources[r.Intn(len(resources))]
			break
		}
	}

	// No compatible resource was found.
	if resource == nil {
		return nil, nil
	}

	// Set that stores the resources that appear in the same calls with the selected resource.
	relatedRes := map[*ResultArg]bool{resource: true}

	// Remove unrelated calls from the program.
	for idx := len(p.Calls) - 1; idx >= 0; idx-- {
		includeCall := false
		var newResources []*ResultArg
		ForeachArg(p.Calls[idx], func(arg Arg, _ *ArgCtx) {
			if a, ok := arg.(*ResultArg); ok {
				if a.Res != nil && !relatedRes[a.Res] {
					newResources = append(newResources, a.Res)
				}
				if relatedRes[a] || relatedRes[a.Res] {
					includeCall = true
				}
			}
		})
		if !includeCall {
			p.removeCall(idx)
		} else {
			for _, res := range newResources {
				relatedRes[res] = true
			}
		}
	}

	// Selects a biased random length of the returned calls (more calls could offer more
	// interesting programs). The values returned (n = len(calls): n, n-1, ..., 2.
	biasedLen := 2 + r.biasedRand(len(calls)-1, 10)

	// Removes the references that are not used anymore.
	for i := biasedLen; i < len(calls); i++ {
		p.removeCall(i)
	}

	return MakeResultArg(t, resource, 0), p.Calls
}

func getCompatibleResources(p *Prog, resourceType string, r *randGen) (resources []*ResultArg) {
	for _, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			// Collect only initialized resources (the ones that are already used in other calls).
			a, ok := arg.(*ResultArg)
			if !ok || len(a.uses) == 0 || a.typ.Dir() != DirOut {
				return
			}
			if !r.target.isCompatibleResource(resourceType, a.typ.Name()) {
				return
			}
			resources = append(resources, a)
		})
	}
	return resources
}
