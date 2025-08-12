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
)

const (
	// "Recommended" number of calls in programs that we try to aim at during fuzzing.
	RecommendedCalls = 30
	// "Recommended" max number of calls in programs.
	// If we receive longer programs from hub/corpus we discard them.
	MaxCalls = 40
	// Maximum number of times we can call the same IOCTL while resolving/creating a resource.
	MaxResSameSyscall = 3
	// Number of times we try to avoid reusing an IOCTL that's already in the stack while resolving/creating a resource.
	AvoidSameSyscallAttempts = 20
)

type randGen struct {
	*rand.Rand
	target                *Target
	inGenerateResource    bool
	patchConditionalDepth int
	recDepth              map[string]int
	EnforceDeps           bool
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
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		64, 127, 128, 129, 255, 256, 257, 511, 512,
		1023, 1024, 1025, 2047, 2048, 4095, 4096,
		(1 << 15) - 1, (1 << 15), (1 << 15) + 1,
		(1 << 16) - 1, (1 << 16), (1 << 16) + 1,
		(1 << 31) - 1, (1 << 31), (1 << 31) + 1,
		(1 << 32) - 1, (1 << 32), (1 << 32) + 1,
		(1 << 63) - 1, (1 << 63), (1 << 63) + 1,
		(1 << 64) - 1,
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

const maxArrayLen = 10

func (r *randGen) randArrayLen() uint64 {
	// biasedRand produces: 10, 9, ..., 1, 0,
	// we want: 1, 2, ..., 9, 10, 0
	return uint64(maxArrayLen-r.biasedRand(maxArrayLen+1, 10)+1) % (maxArrayLen + 1)
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
		n = (r.rand(3) + 1) * r.target.NumPages / 4
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
	// Note: this loop can hang if all values are equal to 0. We don't generate such flags in the compiler now,
	// but it used to hang occasionally, so we keep the try < 10 logic b/c we don't have a local check for values.
	for try := 0; try < 10 && (v == 0 || r.nOutOf(2, 3)); try++ {
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
	if fn != "" && fn[len(fn)-1] == 0 {
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

const specialFileLenPad = "a"

func (r *randGen) filenameImpl(s *state) string {
	if r.oneOf(100) {
		return specialFiles[r.Intn(len(specialFiles))]
	}
	if len(s.files) == 0 || r.oneOf(10) {
		// Generate a new name.
		dir := "."
		if r.oneOf(2) && len(s.files) != 0 {
			dir = r.randFromMap(s.files)
			if dir != "" && dir[len(dir)-1] == 0 {
				dir = dir[:len(dir)-1]
			}
			if r.oneOf(10) && filepath.Clean(dir)[0] != '.' {
				dir += "/.."
			}
		}
		for i := 0; ; i++ {
			f := fmt.Sprintf("%v/file%v", dir, i)
			if r.oneOf(100) {
				// Make file name very long using target.SpecialFileLenghts consts.
				// Add/subtract some small const to account for our file name prefix
				// and potential kernel off-by-one's.
				fileLen := r.randFilenameLength()
				if add := fileLen - len(f); add > 0 {
					f += strings.Repeat(specialFileLenPad, add)
				}
			}
			if !s.files[f] {
				return f
			}
		}
	}
	return r.randFromMap(s.files)
}

func (r *randGen) randFilenameLength() int {
	off := r.biasedRand(10, 5)
	if r.bin() {
		off = -off
	}
	lens := r.target.SpecialFileLenghts
	return max(lens[r.Intn(len(lens))]+off, 0)
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
		if r.nOutOf(10, 11) {
			buf.Write([]byte{punct[r.Intn(len(punct))]})
		} else {
			buf.Write([]byte{byte(r.Intn(256))})
		}
	}
	if r.oneOf(100) == t.NoZ {
		buf.Write([]byte{0})
	}
	return buf.Bytes()
}

func (r *randGen) allocAddr(s *state, typ Type, dir Dir, size uint64, data Arg) *PointerArg {
	return MakePointerArg(typ, dir, s.ma.alloc(r, size, data.Type().Alignment()), data)
}

func (r *randGen) allocVMA(s *state, typ Type, dir Dir, numPages uint64) *PointerArg {
	page := s.va.alloc(r, numPages)
	return MakeVmaPointerArg(typ, dir, page*r.target.PageSize, numPages*r.target.PageSize)
}

func (r *randGen) pruneRecursion(name string) (bool, func()) {
	if r.recDepth[name] >= 2 {
		return false, nil
	}
	r.recDepth[name]++
	return true, func() {
		r.recDepth[name]--
		if r.recDepth[name] == 0 {
			delete(r.recDepth, name)
		}
	}
}

func (r *randGen) createResource(s *state, res *ResourceType, dir Dir) (Arg, []*Call) {
	if !r.inGenerateResource {
		panic("inGenerateResource is not set")
	}
	kind := res.Desc.Name
	// Find calls that produce the necessary resources.
	ctors := r.enabledCtors(s, kind)
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
		kind1 := all[r.Intn(len(all))]
		ctors1 := r.enabledCtors(s, kind1)
		if len(ctors1) != 0 {
			// Don't use the resource for which we don't have any ctors.
			// It's fine per-se because below we just return nil in such case.
			// But in TestCreateResource tests we want to ensure that we don't fail
			// to create non-optional resources, and if we spoof a non-optional
			// resource with ctors with a optional resource w/o ctors, then that check will fail.
			kind, ctors = kind1, ctors1
		}
	}
	if len(ctors) == 0 {
		// We may not have any constructors for optional input resources because we don't disable
		// syscalls based on optional inputs resources w/o ctors in TransitivelyEnabledCalls.
		return nil, nil
	}
	// Now we have a set of candidate calls that can create the necessary resource.
	// Generate one of them.
	var meta *Syscall
	// Prefer precise constructors.
	var precise []*Syscall
	for _, info := range ctors {
		if info.Precise {
			if r.EnforceDeps && isSyscallInStack(s, info.Call.Name) {
				continue
			}
			precise = append(precise, info.Call)
		}
	}
	for i := 0; i < AvoidSameSyscallAttempts; i++ {
		if len(precise) > 0 {
			// If the argument is optional, it's not guaranteed that there'd be a
			// precise constructor.
			meta = precise[r.Intn(len(precise))]
		}
		if meta == nil || r.oneOf(3) {
			// Sometimes just take a random one.
			meta = ctors[r.Intn(len(ctors))].Call
		}

		if !r.EnforceDeps || !isSyscallInStack(s, meta.Name) {
			break
		}
	}

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
	sort.SliceStable(allres, func(i, j int) bool {
		return allres[i].Type().Name() < allres[j].Type().Name()
	})
	if len(allres) == 0 {
		panic(fmt.Sprintf("failed to create a resource %v (%v) with %v",
			res.Desc.Kind[0], kind, meta.Name))
	}
	arg := MakeResultArg(res, dir, allres[r.Intn(len(allres))], 0)
	for _, rRes := range allres {
		if rRes.Dir() != DirIn {
			s.resources[kind] = append(s.resources[kind], rRes)
		}
	}
	return arg, calls
}

func (r *randGen) enabledCtors(s *state, kind string) []ResourceCtor {
	var ret []ResourceCtor
	for _, info := range r.target.resourceCtors[kind] {
		if s.ct.Generatable(info.Call.ID) {
			ret = append(ret, info)
		}
	}
	return ret
}

func (r *randGen) generateText(kind TextKind) []byte {
	switch kind {
	case TextTarget:
		if cfg := createTargetIfuzzConfig(r.target); cfg != nil {
			return ifuzz.Generate(cfg, r.Rand)
		}
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
		if cfg := createTargetIfuzzConfig(r.target); cfg != nil {
			return ifuzz.Mutate(cfg, r.Rand, text)
		}
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
		cfg.Arch = ifuzz.ArchX86
	case "386":
		cfg.Mode = ifuzz.ModeProt32
		cfg.Arch = ifuzz.ArchX86
	case "ppc64":
		cfg.Mode = ifuzz.ModeLong64
		cfg.Arch = ifuzz.ArchPowerPC
	case "arm64":
		cfg.Mode = ifuzz.ModeLong64
		cfg.Arch = ifuzz.ArchArm64
	default:
		return nil
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
		cfg.Arch = ifuzz.ArchX86
	case TextX86bit16:
		cfg.Mode = ifuzz.ModeProt16
		cfg.Arch = ifuzz.ArchX86
	case TextX86bit32:
		cfg.Mode = ifuzz.ModeProt32
		cfg.Arch = ifuzz.ArchX86
	case TextX86bit64:
		cfg.Mode = ifuzz.ModeLong64
		cfg.Arch = ifuzz.ArchX86
	case TextPpc64:
		cfg.Mode = ifuzz.ModeLong64
		cfg.Arch = ifuzz.ArchPowerPC
	case TextArm64:
		cfg.Mode = ifuzz.ModeLong64
		cfg.Arch = ifuzz.ArchArm64
	default:
		panic(fmt.Sprintf("unknown text kind: %v", kind))
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
	biasCall := -1
	if insertionPoint > 0 {
		// Choosing the base call is based on the insertion point of the new calls sequence.
		insertionCall := p.Calls[r.Intn(insertionPoint)].Meta
		if !insertionCall.Attrs.NoGenerate {
			// We must be careful not to bias towards a non-generatable call.
			biasCall = insertionCall.ID
		}
	}
	idx := s.ct.choose(r.Rand, biasCall)
	meta := r.target.Syscalls[idx]
	return r.generateParticularCall(s, meta)
}

func (r *randGen) generateParticularCall(s *state, meta *Syscall) (calls []*Call) {
	if meta.Attrs.Disabled {
		panic(fmt.Sprintf("generating disabled call %v", meta.Name))
	}
	if meta.Attrs.NoGenerate {
		panic(fmt.Sprintf("generating no_generate call: %v", meta.Name))
	}
	c := MakeCall(meta, nil)
	pushSyscallToStack(s, meta.Name)
	c.Args, calls = r.generateArgs(s, meta.Args, DirIn)
	popSyscallFromStack(s)
	moreCalls, _ := r.patchConditionalFields(c, s)
	r.target.assignSizesCall(c)
	return append(append(calls, moreCalls...), c)
}

// GenerateAllSyzProg generates a program that contains all pseudo syz_ calls for testing.
func (target *Target) GenerateAllSyzProg(rs rand.Source) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, target.DefaultChoiceTable(), nil)
	for _, meta := range target.PseudoSyscalls() {
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

// PseudoSyscalls selects one *Syscall for each pseudosyscall.
func (target *Target) PseudoSyscalls() []*Syscall {
	handled := make(map[string]bool)
	var ret []*Syscall
	for _, meta := range target.Syscalls {
		if !strings.HasPrefix(meta.CallName, "syz_") ||
			handled[meta.CallName] ||
			meta.Attrs.Disabled ||
			meta.Attrs.NoGenerate {
			continue
		}
		ret = append(ret, meta)
		handled[meta.CallName] = true
	}
	return ret
}

// GenSampleProg generates a single sample program for the call.
func (target *Target) GenSampleProg(meta *Syscall, rs rand.Source) *Prog {
	r := newRand(target, rs)
	s := newState(target, target.DefaultChoiceTable(), nil)
	p := &Prog{
		Target: target,
	}
	for _, c := range r.generateParticularCall(s, meta) {
		s.analyze(c)
		p.Calls = append(p.Calls, c)
	}
	if err := p.validate(); err != nil {
		panic(err)
	}
	return p
}

// DataMmapProg creates program that maps data segment.
// Also used for testing as the simplest program.
func (target *Target) DataMmapProg() *Prog {
	return &Prog{
		Target:   target,
		Calls:    target.MakeDataMmap(),
		isUnsafe: true,
	}
}

func (r *randGen) generateArgs(s *state, fields []Field, dir Dir) ([]Arg, []*Call) {
	var calls []*Call
	args := make([]Arg, len(fields))

	// Generate all args. Size args have the default value 0 for now.
	for i, field := range fields {
		pushFieldToStack(s, field.Name)
		arg, calls1 := r.generateArg(s, field.Type, field.Dir(dir))
		if arg == nil {
			panic(fmt.Sprintf("generated arg is nil for field '%v', fields: %+v", field.Type.Name(), fields))
		}
		popFieldFromStack(s)
		args[i] = arg
		calls = append(calls, calls1...)
	}

	return args, calls
}

func (r *randGen) generateArg(s *state, typ Type, dir Dir) (arg Arg, calls []*Call) {
	return r.generateArgImpl(s, typ, dir, false)
}

func (r *randGen) generateArgImpl(s *state, typ Type, dir Dir, ignoreSpecial bool) (arg Arg, calls []*Call) {
	if dir == DirOut {
		// No need to generate something interesting for output scalar arguments.
		// But we still need to generate the argument itself so that it can be referenced
		// in subsequent calls. For the same reason we do generate pointer/array/struct
		// output arguments (their elements can be referenced in subsequent calls).
		switch typ.(type) {
		case *IntType, *FlagsType, *ConstType, *ProcType, *VmaType, *ResourceType:
			return typ.DefaultArg(dir), nil
		}
	}

	if typ.Optional() && r.oneOf(5) {
		if res, ok := typ.(*ResourceType); ok {
			v := res.Desc.Values[r.Intn(len(res.Desc.Values))]
			return MakeResultArg(typ, dir, nil, v), nil
		}
		return typ.DefaultArg(dir), nil
	}

	if !ignoreSpecial && dir != DirOut {
		switch typ.(type) {
		case *StructType, *UnionType:
			if gen := r.target.SpecialTypes[typ.Name()]; gen != nil {
				return gen(&Gen{r, s}, typ, dir, nil)
			}
		}
	}

	return typ.generate(r, s, dir)
}

func (a *ResourceType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	canRecurse := false
	if !r.inGenerateResource {
		// Don't allow recursion for resourceCentric/createResource.
		// That can lead to generation of huge programs and may be very slow
		// (esp. if we are generating some failing attempts in createResource already).
		r.inGenerateResource = true
		defer func() { r.inGenerateResource = false }()
		canRecurse = true
	}
	if (canRecurse && r.nOutOf(8, 10)) ||
		(!canRecurse && r.nOutOf(19, 20)) ||
		r.EnforceDeps {
		arg = r.existingResource(s, a, dir)
		if arg != nil {
			return
		}
	}
	if r.EnforceDeps && !canRecurse {
		recCounter := getSyscallFieldLoopIterations(s)
		canRecurse = (recCounter < MaxResSameSyscall)
	}
	if canRecurse {
		if r.oneOf(4) {
			arg, calls = r.resourceCentric(s, a, dir)
			if arg != nil {
				return
			}
		}
		if r.nOutOf(4, 5) || r.EnforceDeps {
			// If we could not reuse a resource, let's prefer resource creation over
			// random int substitution.
			arg, calls = r.createResource(s, a, dir)
			if arg != nil {
				return
			}
		}
	}
	special := a.SpecialValues()
	arg = MakeResultArg(a, dir, nil, special[r.Intn(len(special))])
	return
}

func (a *BufferType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	switch a.Kind {
	case BufferBlobRand, BufferBlobRange:
		sz := r.randBufLen()
		if a.Kind == BufferBlobRange {
			sz = r.randRange(a.RangeBegin, a.RangeEnd)
		}
		if dir == DirOut {
			return MakeOutDataArg(a, dir, sz), nil
		}
		data := make([]byte, sz)
		for i := range data {
			data[i] = byte(r.Intn(256))
		}
		return MakeDataArg(a, dir, data), nil
	case BufferString:
		data := r.randString(s, a)
		if dir == DirOut {
			return MakeOutDataArg(a, dir, uint64(len(data))), nil
		}
		return MakeDataArg(a, dir, data), nil
	case BufferFilename:
		if dir == DirOut {
			var sz uint64
			switch {
			case !a.Varlen():
				sz = a.Size()
			case r.nOutOf(1, 3):
				sz = r.rand(100)
			default:
				sz = uint64(r.randFilenameLength())
			}
			return MakeOutDataArg(a, dir, sz), nil
		}
		return MakeDataArg(a, dir, []byte(r.filename(s, a))), nil
	case BufferGlob:
		return MakeDataArg(a, dir, r.randString(s, a)), nil
	case BufferText:
		if dir == DirOut {
			return MakeOutDataArg(a, dir, uint64(r.Intn(100))), nil
		}
		return MakeDataArg(a, dir, r.generateText(a.Text)), nil
	case BufferCompressed:
		panic(fmt.Sprintf("can't generate compressed type %v", a))
	default:
		panic("unknown buffer kind")
	}
}

func (a *VmaType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	npages := r.randPageCount()
	if a.RangeBegin != 0 || a.RangeEnd != 0 {
		npages = a.RangeBegin + uint64(r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
	}
	return r.allocVMA(s, a, dir, npages), nil
}

func (a *FlagsType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	return MakeConstArg(a, dir, r.flags(a.Vals, a.BitMask, 0)), nil
}

func (a *ConstType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	return MakeConstArg(a, dir, a.Val), nil
}

func (a *IntType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	bits := a.TypeBitSize()
	v := r.randInt(bits)
	switch a.Kind {
	case IntRange:
		v = r.randRangeInt(a.RangeBegin, a.RangeEnd, bits, a.Align)
	}
	return MakeConstArg(a, dir, v), nil
}

func (a *ProcType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	return MakeConstArg(a, dir, r.rand(int(a.ValuesPerProc))), nil
}

func (a *ArrayType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	// Allow infinite recursion for arrays.
	switch a.Elem.(type) {
	case *StructType, *ArrayType, *UnionType:
		ok, release := r.pruneRecursion(a.Elem.Name())
		if !ok {
			return MakeGroupArg(a, dir, nil), nil
		}
		defer release()
	}
	var count uint64
	switch a.Kind {
	case ArrayRandLen:
		count = r.randArrayLen()
	case ArrayRangeLen:
		count = r.randRange(a.RangeBegin, a.RangeEnd)
	}
	// The resource we are trying to generate may be in the array elements, so create at least 1.
	if r.inGenerateResource && count == 0 {
		count = 1
	}
	var inner []Arg
	for i := uint64(0); i < count; i++ {
		arg1, calls1 := r.generateArg(s, a.Elem, dir)
		inner = append(inner, arg1)
		calls = append(calls, calls1...)
	}
	return MakeGroupArg(a, dir, inner), calls
}

func (a *StructType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	args, calls := r.generateArgs(s, a.Fields, dir)
	group := MakeGroupArg(a, dir, args)
	return group, calls
}

func (a *UnionType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	if a.isConditional() {
		// Conditions may reference other fields that may not have already
		// been generated. We'll fill them in later.
		return a.DefaultArg(dir), nil
	}
	index := r.Intn(len(a.Fields))
	optType, optDir := a.Fields[index].Type, a.Fields[index].Dir(dir)
	opt, calls := r.generateArg(s, optType, optDir)
	return MakeUnionArg(a, dir, opt, index), calls
}

func (a *PtrType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	// Allow infinite recursion for optional pointers.
	if a.Optional() {
		switch a.Elem.(type) {
		case *StructType, *ArrayType, *UnionType:
			ok, release := r.pruneRecursion(a.Elem.Name())
			if !ok {
				return MakeSpecialPointerArg(a, dir, 0), nil
			}
			defer release()
		}
	}
	// The resource we are trying to generate may be in the pointer,
	// so don't try to create an empty special pointer during resource generation.
	if !r.EnforceDeps && !r.inGenerateResource && r.oneOf(1000) {
		index := r.rand(len(r.target.SpecialPointers))
		return MakeSpecialPointerArg(a, dir, index), nil
	}
	inner, calls := r.generateArg(s, a.Elem, a.ElemDir)
	arg = r.allocAddr(s, a, dir, inner.Size(), inner)
	return arg, calls
}

func (a *LenType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	// Updated later in assignSizesCall.
	return MakeConstArg(a, dir, 0), nil
}

func (a *CsumType) generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call) {
	// Filled at runtime by executor.
	return MakeConstArg(a, dir, 0), nil
}

func (r *randGen) existingResource(s *state, res *ResourceType, dir Dir) Arg {
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
	return MakeResultArg(res, dir, allres[r.Intn(len(allres))], 0)
}

// Finds a compatible resource with the type `t` and the calls that initialize that resource.
func (r *randGen) resourceCentric(s *state, t *ResourceType, dir Dir) (arg Arg, calls []*Call) {
	var p *Prog
	var resource *ResultArg
	for _, idx := range r.Perm(len(s.corpus)) {
		corpusProg := s.corpus[idx]
		resources := getCompatibleResources(corpusProg, t.TypeName, r)
		if len(resources) == 0 {
			continue
		}
		argMap := make(map[*ResultArg]*ResultArg)
		p = corpusProg.cloneWithMap(argMap)
		resource = argMap[resources[r.Intn(len(resources))]]
		break
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
			p.RemoveCall(idx)
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
		p.RemoveCall(i)
	}

	return MakeResultArg(t, dir, resource, 0), p.Calls
}

func getCompatibleResources(p *Prog, resourceType string, r *randGen) (resources []*ResultArg) {
	for _, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			// Collect only initialized resources (the ones that are already used in other calls).
			a, ok := arg.(*ResultArg)
			if !ok || len(a.uses) == 0 || a.Dir() != DirOut {
				return
			}
			if !r.target.isCompatibleResource(resourceType, a.Type().Name()) {
				return
			}
			resources = append(resources, a)
		})
	}
	return resources
}
