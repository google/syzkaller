// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"

	"github.com/google/syzkaller/ifuzz"
	"github.com/google/syzkaller/sys"
)

var pageStartPool = sync.Pool{New: func() interface{} { return new([]uintptr) }}

type randGen struct {
	*rand.Rand
	inCreateResource bool
}

func newRand(rs rand.Source) *randGen {
	return &randGen{rand.New(rs), false}
}

func (r *randGen) rand(n int) uintptr {
	return uintptr(r.Intn(n))
}

func (r *randGen) randRange(begin int, end int) uintptr {
	return uintptr(begin + r.Intn(end-begin+1))
}

func (r *randGen) bin() bool {
	return r.Intn(2) == 0
}

func (r *randGen) oneOf(n int) bool {
	return r.Intn(n) == 0
}

func (r *randGen) rand64() uintptr {
	v := uintptr(r.Int63())
	if r.bin() {
		v |= 1 << 63
	}
	return v
}

// Some potentially interesting integers.
var specialInts = []uintptr{
	0, 1, 31, 32, 63, 64, 127, 128,
	129, 255, 256, 257, 511, 512,
	1023, 1024, 1025, 2047, 2048, 4095, 4096,
	(1 << 15) - 1, (1 << 15), (1 << 15) + 1,
	(1 << 16) - 1, (1 << 16), (1 << 16) + 1,
	(1 << 31) - 1, (1 << 31), (1 << 31) + 1,
	(1 << 32) - 1, (1 << 32), (1 << 32) + 1,
}

func (r *randGen) randInt() uintptr {
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
		v = uintptr(-int(v))
	default:
		v <<= uint(r.Intn(63))
	}
	return v
}

func (r *randGen) randRangeInt(begin int64, end int64) uintptr {
	if r.oneOf(100) {
		return r.randInt()
	}
	return uintptr(begin + r.Int63n(end-begin+1))
}

// biasedRand returns a random int in range [0..n),
// probability of n-1 is k times higher than probability of 0.
func (r *randGen) biasedRand(n, k int) int {
	nf, kf := float64(n), float64(k)
	rf := nf * (kf/2 + 1) * rand.Float64()
	bf := (-1 + math.Sqrt(1+2*kf*rf/nf)) * nf / kf
	return int(bf)
}

func (r *randGen) randArrayLen() uintptr {
	const maxLen = 10
	// biasedRand produces: 10, 9, ..., 1, 0,
	// we want: 1, 2, ..., 9, 10, 0
	return uintptr(maxLen-r.biasedRand(maxLen+1, 10)+1) % (maxLen + 1)
}

func (r *randGen) randBufLen() (n uintptr) {
	switch {
	case r.nOutOf(50, 56):
		n = r.rand(256)
	case r.nOutOf(5, 6):
		n = 4 << 10
	}
	return
}

func (r *randGen) randPageCount() (n uintptr) {
	switch {
	case r.nOutOf(100, 106):
		n = r.rand(4) + 1
	case r.nOutOf(5, 6):
		n = r.rand(20) + 1
	default:
		n = (r.rand(3) + 1) * 1024
	}
	return
}

func (r *randGen) flags(vv []uintptr) (v uintptr) {
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

func (r *randGen) filename(s *state) string {
	// TODO: support procfs and sysfs
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
	if len(s.files) == 0 || r.oneOf(10) {
		// Generate a new name.
		for i := 0; ; i++ {
			f := fmt.Sprintf("%v/file%v\x00", dir, i)
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

func (r *randGen) randString(s *state, vals []string, dir sys.Dir) []byte {
	data := r.randStringImpl(s, vals)
	if dir == sys.DirOut {
		for i := range data {
			data[i] = 0
		}
	}
	return data
}

func (r *randGen) randStringImpl(s *state, vals []string) []byte {
	if len(vals) != 0 {
		return []byte(vals[r.Intn(len(vals))])
	}
	if len(s.strings) != 0 && r.bin() {
		// Return an existing string.
		strings := make([]string, 0, len(s.strings))
		for s := range s.strings {
			strings = append(strings, s)
		}
		return []byte(strings[r.Intn(len(strings))])
	}
	dict := []string{"user", "keyring", "trusted", "system", "security", "selinux",
		"posix_acl_access", "mime_type", "md5sum", "nodev", "self",
		"bdev", "proc", "cgroup", "cpuset",
		"lo", "eth0", "eth1", "em0", "em1", "wlan0", "wlan1", "ppp0", "ppp1",
		"vboxnet0", "vboxnet1", "vmnet0", "vmnet1", "GPL"}
	punct := []byte{'!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '\\',
		'/', ':', '.', ',', '-', '\'', '[', ']', '{', '}'}
	buf := new(bytes.Buffer)
	for r.nOutOf(3, 4) {
		switch {
		case r.nOutOf(10, 21):
			buf.WriteString(dict[r.Intn(len(dict))])
		case r.nOutOf(10, 11):
			buf.Write([]byte{punct[r.Intn(len(punct))]})
		default:
			buf.Write([]byte{byte(r.Intn(256))})
		}
	}
	if !r.oneOf(100) {
		buf.Write([]byte{0})
	}
	return buf.Bytes()
}

func isSpecialStruct(typ sys.Type) func(r *randGen, s *state) (*Arg, []*Call) {
	a, ok := typ.(*sys.StructType)
	if !ok {
		panic("must be a struct")
	}
	switch typ.Name() {
	case "timespec":
		return func(r *randGen, s *state) (*Arg, []*Call) {
			return r.timespec(s, a, false)
		}
	case "timeval":
		return func(r *randGen, s *state) (*Arg, []*Call) {
			return r.timespec(s, a, true)
		}
	}
	return nil
}

func (r *randGen) timespec(s *state, typ *sys.StructType, usec bool) (arg *Arg, calls []*Call) {
	// We need to generate timespec/timeval that are either (1) definitely in the past,
	// or (2) definitely in unreachable fututre, or (3) few ms ahead of now.
	// Note timespec/timeval can be absolute or relative to now.
	switch {
	case r.nOutOf(1, 4):
		// now for relative, past for absolute
		arg = groupArg(typ, []*Arg{
			constArg(typ.Fields[0], 0),
			constArg(typ.Fields[1], 0),
		})
	case r.nOutOf(1, 3):
		// few ms ahead for relative, past for absolute
		nsec := uintptr(10 * 1e6)
		if usec {
			nsec /= 1e3
		}
		arg = groupArg(typ, []*Arg{
			constArg(typ.Fields[0], 0),
			constArg(typ.Fields[1], nsec),
		})
	case r.nOutOf(1, 2):
		// unreachable fututre for both relative and absolute
		arg = groupArg(typ, []*Arg{
			constArg(typ.Fields[0], 2e9),
			constArg(typ.Fields[1], 0),
		})
	default:
		// few ms ahead for absolute
		meta := sys.CallMap["clock_gettime"]
		ptrArgType := meta.Args[1].(*sys.PtrType)
		argType := ptrArgType.Type.(*sys.StructType)
		tp := groupArg(argType, []*Arg{
			constArg(argType.Fields[0], 0),
			constArg(argType.Fields[1], 0),
		})
		var tpaddr *Arg
		tpaddr, calls = r.addr(s, ptrArgType, 2*ptrSize, tp)
		gettime := &Call{
			Meta: meta,
			Args: []*Arg{
				constArg(meta.Args[0], sys.CLOCK_REALTIME),
				tpaddr,
			},
			Ret: returnArg(meta.Ret),
		}
		calls = append(calls, gettime)
		sec := resultArg(typ.Fields[0], tp.Inner[0])
		nsec := resultArg(typ.Fields[1], tp.Inner[1])
		if usec {
			nsec.OpDiv = 1e3
			nsec.OpAdd = 10 * 1e3
		} else {
			nsec.OpAdd = 10 * 1e6
		}
		arg = groupArg(typ, []*Arg{sec, nsec})
	}
	return
}

// createMmapCall creates a "normal" mmap call that maps [start, start+npages) page range.
func createMmapCall(start, npages uintptr) *Call {
	meta := sys.CallMap["mmap"]
	mmap := &Call{
		Meta: meta,
		Args: []*Arg{
			pointerArg(meta.Args[0], start, 0, npages, nil),
			pageSizeArg(meta.Args[1], npages, 0),
			constArg(meta.Args[2], sys.PROT_READ|sys.PROT_WRITE),
			constArg(meta.Args[3], sys.MAP_ANONYMOUS|sys.MAP_PRIVATE|sys.MAP_FIXED),
			constArg(meta.Args[4], sys.InvalidFD),
			constArg(meta.Args[5], 0),
		},
		Ret: returnArg(meta.Ret),
	}
	return mmap
}

func (r *randGen) addr1(s *state, typ sys.Type, size uintptr, data *Arg) (*Arg, []*Call) {
	npages := (size + pageSize - 1) / pageSize
	if npages == 0 {
		npages = 1
	}
	if r.bin() {
		return r.randPageAddr(s, typ, npages, data, false), nil
	}
	for i := uintptr(0); i < maxPages-npages; i++ {
		free := true
		for j := uintptr(0); j < npages; j++ {
			if s.pages[i+j] {
				free = false
				break
			}
		}
		if !free {
			continue
		}
		c := createMmapCall(i, npages)
		return pointerArg(typ, i, 0, 0, data), []*Call{c}
	}
	return r.randPageAddr(s, typ, npages, data, false), nil
}

func (r *randGen) addr(s *state, typ sys.Type, size uintptr, data *Arg) (*Arg, []*Call) {
	arg, calls := r.addr1(s, typ, size, data)
	if arg.Kind != ArgPointer {
		panic("bad")
	}
	// Patch offset of the address.
	switch {
	case r.nOutOf(50, 102):
	case r.nOutOf(50, 52):
		arg.AddrOffset = -int(size)
	case r.nOutOf(1, 2):
		arg.AddrOffset = r.Intn(pageSize)
	default:
		if size > 0 {
			arg.AddrOffset = -r.Intn(int(size))
		}
	}
	return arg, calls
}

func (r *randGen) randPageAddr(s *state, typ sys.Type, npages uintptr, data *Arg, vma bool) *Arg {
	poolPtr := pageStartPool.Get().(*[]uintptr)
	starts := (*poolPtr)[:0]
	for i := uintptr(0); i < maxPages-npages; i++ {
		busy := true
		for j := uintptr(0); j < npages; j++ {
			if !s.pages[i+j] {
				busy = false
				break
			}
		}
		// TODO: it does not need to be completely busy,
		// for example, mmap addr arg can be new memory.
		if !busy {
			continue
		}
		starts = append(starts, i)
	}
	*poolPtr = starts
	pageStartPool.Put(poolPtr)
	var page uintptr
	if len(starts) != 0 {
		page = starts[r.rand(len(starts))]
	} else {
		page = r.rand(int(maxPages - npages))
	}
	if !vma {
		npages = 0
	}
	return pointerArg(typ, page, 0, npages, data)
}

func (r *randGen) createResource(s *state, res *sys.ResourceType) (arg *Arg, calls []*Call) {
	if r.inCreateResource {
		special := res.SpecialValues()
		return constArg(res, special[r.Intn(len(special))]), nil
	}
	r.inCreateResource = true
	defer func() { r.inCreateResource = false }()

	kind := res.Desc.Name
	if r.oneOf(1000) {
		// Spoof resource subkind.
		var all []string
		for kind1 := range sys.Resources {
			if sys.IsCompatibleResource(res.Desc.Kind[0], kind1) {
				all = append(all, kind1)
			}
		}
		kind = all[r.Intn(len(all))]
	}
	// Find calls that produce the necessary resources.
	metas0 := sys.ResourceConstructors(kind)
	// TODO: reduce priority of less specialized ctors.
	var metas []*sys.Call
	for _, meta := range metas0 {
		if s.ct == nil || s.ct.run[meta.ID] == nil {
			continue
		}
		metas = append(metas, meta)
	}
	if len(metas) == 0 {
		return constArg(res, res.Default()), nil
	}

	// Now we have a set of candidate calls that can create the necessary resource.
	for i := 0; i < 1e3; i++ {
		// Generate one of them.
		meta := metas[r.Intn(len(metas))]
		calls := r.generateParticularCall(s, meta)
		s1 := newState(s.ct)
		s1.analyze(calls[len(calls)-1])
		// Now see if we have what we want.
		var allres []*Arg
		for kind1, res1 := range s1.resources {
			if sys.IsCompatibleResource(kind, kind1) {
				allres = append(allres, res1...)
			}
		}
		if len(allres) != 0 {
			// Bingo!
			arg := resultArg(res, allres[r.Intn(len(allres))])
			return arg, calls
		}
		switch meta.Name {
		// Return resources in a variable-length array (length can be 0).
		case "getgroups", "ioctl$DRM_IOCTL_RES_CTX":
		default:
			panic(fmt.Sprintf("unexpected call failed to create a resource %v: %v", kind, meta.Name))
		}
		// Discard unsuccessful calls.
		for _, c := range calls {
			foreachArg(c, func(arg, _ *Arg, _ *[]*Arg) {
				if arg.Kind == ArgResult {
					delete(arg.Res.Uses, arg)
				}
			})
		}
	}
	// Generally we can loop several times, e.g. when we choose a call that returns
	// the resource in an array, but then generateArg generated that array of zero length.
	// But we must succeed eventually.
	panic("failed to create a resource")
}

func (r *randGen) generateText(kind sys.TextKind) []byte {
	switch kind {
	case sys.Text_arm64:
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

func (r *randGen) mutateText(kind sys.TextKind, text []byte) []byte {
	switch kind {
	case sys.Text_arm64:
		return mutateData(r, text, 40, 60)
	default:
		cfg := createIfuzzConfig(kind)
		return ifuzz.Mutate(cfg, r.Rand, text)
	}
}

func createIfuzzConfig(kind sys.TextKind) *ifuzz.Config {
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
	case sys.Text_x86_real:
		cfg.Mode = ifuzz.ModeReal16
	case sys.Text_x86_16:
		cfg.Mode = ifuzz.ModeProt16
	case sys.Text_x86_32:
		cfg.Mode = ifuzz.ModeProt32
	case sys.Text_x86_64:
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
	call := -1
	if len(p.Calls) != 0 {
		for i := 0; i < 5; i++ {
			c := p.Calls[r.Intn(len(p.Calls))].Meta
			call = c.ID
			// There is roughly half of mmap's so ignore them.
			if c.Name != "mmap" {
				break
			}
		}
	}
	meta := sys.Calls[s.ct.Choose(r.Rand, call)]
	return r.generateParticularCall(s, meta)
}

func (r *randGen) generateParticularCall(s *state, meta *sys.Call) (calls []*Call) {
	c := &Call{
		Meta: meta,
		Ret:  returnArg(meta.Ret),
	}
	c.Args, calls = r.generateArgs(s, meta.Args)
	assignSizesCall(c)
	calls = append(calls, c)
	for _, c1 := range calls {
		sanitizeCall(c1)
	}
	return calls
}

// GenerateAllSyzProg generates a program that contains all pseudo syz_ calls for testing.
func GenerateAllSyzProg(rs rand.Source) *Prog {
	p := new(Prog)
	r := newRand(rs)
	s := newState(nil)
	handled := make(map[string]bool)
	for _, meta := range sys.Calls {
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

func (r *randGen) generateArgs(s *state, types []sys.Type) ([]*Arg, []*Call) {
	var calls []*Call
	args := make([]*Arg, len(types))

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

func (r *randGen) generateArg(s *state, typ sys.Type) (arg *Arg, calls []*Call) {
	if typ.Dir() == sys.DirOut {
		// No need to generate something interesting for output scalar arguments.
		// But we still need to generate the argument itself so that it can be referenced
		// in subsequent calls. For the same reason we do generate pointer/array/struct
		// output arguments (their elements can be referenced in subsequent calls).
		switch typ.(type) {
		case *sys.IntType, *sys.FlagsType, *sys.ConstType,
			*sys.ResourceType, *sys.VmaType, *sys.ProcType:
			return constArg(typ, typ.Default()), nil
		}
	}

	if typ.Optional() && r.oneOf(5) {
		if _, ok := typ.(*sys.BufferType); ok {
			panic("impossible") // parent PtrType must be Optional instead
		}
		return constArg(typ, typ.Default()), nil
	}

	switch a := typ.(type) {
	case *sys.ResourceType:
		switch {
		case r.nOutOf(1000, 1011):
			// Get an existing resource.
			var allres []*Arg
			for name1, res1 := range s.resources {
				if sys.IsCompatibleResource(a.Desc.Name, name1) ||
					r.oneOf(20) && sys.IsCompatibleResource(a.Desc.Kind[0], name1) {
					allres = append(allres, res1...)
				}
			}
			if len(allres) != 0 {
				arg = resultArg(a, allres[r.Intn(len(allres))])
			} else {
				arg, calls = r.createResource(s, a)
			}
		case r.nOutOf(10, 11):
			// Create a new resource.
			arg, calls = r.createResource(s, a)
		default:
			special := a.SpecialValues()
			arg = constArg(a, special[r.Intn(len(special))])
		}
		return arg, calls
	case *sys.BufferType:
		switch a.Kind {
		case sys.BufferBlobRand, sys.BufferBlobRange:
			sz := r.randBufLen()
			if a.Kind == sys.BufferBlobRange {
				sz = r.randRange(int(a.RangeBegin), int(a.RangeEnd))
			}
			data := make([]byte, sz)
			if a.Dir() != sys.DirOut {
				for i := range data {
					data[i] = byte(r.Intn(256))
				}
			}
			return dataArg(a, data), nil
		case sys.BufferString:
			data := r.randString(s, a.Values, a.Dir())
			return dataArg(a, data), nil
		case sys.BufferFilename:
			var data []byte
			if a.Dir() == sys.DirOut {
				switch {
				case r.nOutOf(1, 3):
					data = make([]byte, r.Intn(100))
				case r.nOutOf(1, 2):
					data = make([]byte, 108) // UNIX_PATH_MAX
				default:
					data = make([]byte, 4096) // PATH_MAX
				}
			} else {
				data = []byte(r.filename(s))
			}
			return dataArg(a, data), nil
		case sys.BufferText:
			return dataArg(a, r.generateText(a.Text)), nil
		default:
			panic("unknown buffer kind")
		}
	case *sys.VmaType:
		npages := r.randPageCount()
		if a.RangeBegin != 0 || a.RangeEnd != 0 {
			npages = uintptr(int(a.RangeBegin) + r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
		}
		arg := r.randPageAddr(s, a, npages, nil, true)
		return arg, nil
	case *sys.FlagsType:
		return constArg(a, r.flags(a.Vals)), nil
	case *sys.ConstType:
		return constArg(a, a.Val), nil
	case *sys.IntType:
		v := r.randInt()
		switch a.Kind {
		case sys.IntSignalno:
			v %= 130
		case sys.IntFileoff:
			switch {
			case r.nOutOf(90, 101):
				v = 0
			case r.nOutOf(10, 11):
				v = r.rand(100)
			default:
				v = r.randInt()
			}
		case sys.IntRange:
			v = r.randRangeInt(a.RangeBegin, a.RangeEnd)
		}
		return constArg(a, v), nil
	case *sys.ProcType:
		return constArg(a, r.rand(int(a.ValuesPerProc))), nil
	case *sys.ArrayType:
		count := uintptr(0)
		switch a.Kind {
		case sys.ArrayRandLen:
			count = r.randArrayLen()
		case sys.ArrayRangeLen:
			count = r.randRange(int(a.RangeBegin), int(a.RangeEnd))
		}
		var inner []*Arg
		var calls []*Call
		for i := uintptr(0); i < count; i++ {
			arg1, calls1 := r.generateArg(s, a.Type)
			inner = append(inner, arg1)
			calls = append(calls, calls1...)
		}
		return groupArg(a, inner), calls
	case *sys.StructType:
		if ctor := isSpecialStruct(a); ctor != nil && a.Dir() != sys.DirOut {
			arg, calls = ctor(r, s)
			return
		}
		args, calls := r.generateArgs(s, a.Fields)
		group := groupArg(a, args)
		return group, calls
	case *sys.UnionType:
		optType := a.Options[r.Intn(len(a.Options))]
		opt, calls := r.generateArg(s, optType)
		return unionArg(a, opt, optType), calls
	case *sys.PtrType:
		inner, calls := r.generateArg(s, a.Type)
		if a.Dir() == sys.DirOut && inner == nil {
			// No data, but we should have got size.
			arg, calls1 := r.addr(s, a, inner.Size(), nil)
			calls = append(calls, calls1...)
			return arg, calls
		}
		if a.Type.Name() == "iocb" && len(s.resources["iocbptr"]) != 0 {
			// It is weird, but these are actually identified by kernel by address.
			// So try to reuse a previously used address.
			addrs := s.resources["iocbptr"]
			addr := addrs[r.Intn(len(addrs))]
			arg = pointerArg(a, addr.AddrPage, addr.AddrOffset, addr.AddrPagesNum, inner)
			return arg, calls
		}
		arg, calls1 := r.addr(s, a, inner.Size(), inner)
		calls = append(calls, calls1...)
		return arg, calls
	case *sys.LenType, *sys.CsumType:
		// Return placeholder value of 0 while generating len and csum args.
		return constArg(a, 0), nil
	default:
		panic("unknown argument type")
	}
}
