// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"unsafe"
)

const maxBlobLen = uint64(100 << 10)

func (p *Prog) Mutate(rs rand.Source, ncalls int, ct *ChoiceTable, corpus []*Prog) {
	r := newRand(p.Target, rs)
	ctx := &mutator{
		p:      p,
		r:      r,
		ncalls: ncalls,
		ct:     ct,
		corpus: corpus,
	}
	for stop, ok := false, false; !stop; stop = ok && r.oneOf(3) {
		switch {
		case r.oneOf(5):
			// Not all calls have anything squashable,
			// so this has lower priority in reality.
			ok = ctx.squashAny()
		case r.nOutOf(1, 100):
			ok = ctx.splice()
		case r.nOutOf(20, 31):
			ok = ctx.insertCall()
		case r.nOutOf(10, 11):
			ok = ctx.mutateArg()
		default:
			ok = ctx.removeCall()
		}
	}
	for _, c := range p.Calls {
		p.Target.SanitizeCall(c)
	}
	p.debugValidate()
}

type mutator struct {
	p      *Prog
	r      *randGen
	ncalls int
	ct     *ChoiceTable
	corpus []*Prog
}

func (ctx *mutator) splice() bool {
	p, r := ctx.p, ctx.r
	if len(ctx.corpus) == 0 || len(p.Calls) == 0 {
		return false
	}
	p0 := ctx.corpus[r.Intn(len(ctx.corpus))]
	p0c := p0.Clone()
	idx := r.Intn(len(p.Calls))
	p.Calls = append(p.Calls[:idx], append(p0c.Calls, p.Calls[idx:]...)...)
	for i := len(p.Calls) - 1; i >= ctx.ncalls; i-- {
		p.removeCall(i)
	}
	return true
}

func (ctx *mutator) squashAny() bool {
	p, r := ctx.p, ctx.r
	complexPtrs := p.complexPtrs()
	if len(complexPtrs) == 0 {
		return false
	}
	ptr := complexPtrs[r.Intn(len(complexPtrs))]
	if !p.Target.isAnyPtr(ptr.Type()) {
		p.Target.squashPtr(ptr, true)
	}
	var blobs []*DataArg
	var bases []*PointerArg
	ForeachSubArg(ptr, func(arg Arg, ctx *ArgCtx) {
		if data, ok := arg.(*DataArg); ok && arg.Type().Dir() != DirOut {
			blobs = append(blobs, data)
			bases = append(bases, ctx.Base)
		}
	})
	if len(blobs) == 0 {
		return false
	}
	// TODO(dvyukov): we probably want special mutation for ANY.
	// E.g. merging adjacent ANYBLOBs (we don't create them,
	// but they can appear in future); or replacing ANYRES
	// with a blob (and merging it with adjacent blobs).
	idx := r.Intn(len(blobs))
	arg := blobs[idx]
	base := bases[idx]
	baseSize := base.Res.Size()
	arg.data = mutateData(r, arg.Data(), 0, maxBlobLen)
	// Update base pointer if size has increased.
	if baseSize < base.Res.Size() {
		s := analyze(ctx.ct, p, p.Calls[0])
		newArg := r.allocAddr(s, base.Type(), base.Res.Size(), base.Res)
		*base = *newArg
	}
	return true
}

func (ctx *mutator) insertCall() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) >= ctx.ncalls {
		return false
	}
	idx := r.biasedRand(len(p.Calls)+1, 5)
	var c *Call
	if idx < len(p.Calls) {
		c = p.Calls[idx]
	}
	s := analyze(ctx.ct, p, c)
	calls := r.generateCall(s, p)
	p.insertBefore(c, calls)
	return true
}

func (ctx *mutator) removeCall() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) == 0 {
		return false
	}
	idx := r.Intn(len(p.Calls))
	p.removeCall(idx)
	return true
}

func (ctx *mutator) mutateArg() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) == 0 {
		return false
	}
	c := p.Calls[r.Intn(len(p.Calls))]
	if len(c.Args) == 0 {
		return false
	}
	s := analyze(ctx.ct, p, c)
	updateSizes := true
	for stop, ok := false, false; !stop; stop = ok && r.oneOf(3) {
		ok = true
		ma := &mutationArgs{target: p.Target}
		ForeachArg(c, ma.collectArg)
		if len(ma.args) == 0 {
			return false
		}
		idx := r.Intn(len(ma.args))
		arg, ctx := ma.args[idx], ma.ctxes[idx]
		calls, ok1 := p.Target.mutateArg(r, s, arg, ctx, &updateSizes)
		if !ok1 {
			ok = false
			continue
		}
		p.insertBefore(c, calls)
		if updateSizes {
			p.Target.assignSizesCall(c)
		}
		p.Target.SanitizeCall(c)
	}
	return true
}

func (target *Target) mutateArg(r *randGen, s *state, arg Arg, ctx ArgCtx, updateSizes *bool) ([]*Call, bool) {
	var baseSize uint64
	if ctx.Base != nil {
		baseSize = ctx.Base.Res.Size()
	}
	calls, retry, preserve := arg.Type().mutate(r, s, arg, ctx)
	if retry {
		return nil, false
	}
	if preserve {
		*updateSizes = false
	}
	// Update base pointer if size has increased.
	if base := ctx.Base; base != nil && baseSize < base.Res.Size() {
		newArg := r.allocAddr(s, base.Type(), base.Res.Size(), base.Res)
		replaceArg(base, newArg)
	}
	for _, c := range calls {
		target.SanitizeCall(c)
	}
	return calls, true
}

func regenerate(r *randGen, s *state, arg Arg) (calls []*Call, retry, preserve bool) {
	var newArg Arg
	newArg, calls = r.generateArg(s, arg.Type())
	replaceArg(arg, newArg)
	return
}

func mutateInt(r *randGen, s *state, arg Arg) (calls []*Call, retry, preserve bool) {
	if r.bin() {
		return regenerate(r, s, arg)
	}
	a := arg.(*ConstArg)
	switch {
	case r.nOutOf(1, 3):
		a.Val += uint64(r.Intn(4)) + 1
	case r.nOutOf(1, 2):
		a.Val -= uint64(r.Intn(4)) + 1
	default:
		a.Val ^= 1 << uint64(r.Intn(64))
	}
	return
}

func (t *IntType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return mutateInt(r, s, arg)
}

func (t *FlagsType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return mutateInt(r, s, arg)
}

func (t *LenType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	if !r.mutateSize(arg.(*ConstArg), *ctx.Parent) {
		retry = true
		return
	}
	preserve = true
	return
}

func (t *ResourceType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return regenerate(r, s, arg)
}

func (t *VmaType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return regenerate(r, s, arg)
}

func (t *ProcType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return regenerate(r, s, arg)
}

func (t *BufferType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	a := arg.(*DataArg)
	switch t.Kind {
	case BufferBlobRand, BufferBlobRange:
		data := append([]byte{}, a.Data()...)
		minLen, maxLen := uint64(0), maxBlobLen
		if t.Kind == BufferBlobRange {
			minLen, maxLen = t.RangeBegin, t.RangeEnd
		}
		a.data = mutateData(r, data, minLen, maxLen)
	case BufferString:
		data := append([]byte{}, a.Data()...)
		if r.bin() {
			minLen, maxLen := uint64(0), maxBlobLen
			if t.TypeSize != 0 {
				minLen, maxLen = t.TypeSize, t.TypeSize
			}
			a.data = mutateData(r, data, minLen, maxLen)
		} else {
			a.data = r.randString(s, t)
		}
	case BufferFilename:
		a.data = []byte(r.filename(s, t))
	case BufferText:
		data := append([]byte{}, a.Data()...)
		a.data = r.mutateText(t.Text, data)
	default:
		panic("unknown buffer kind")
	}
	return
}

func (t *ArrayType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	// TODO: swap elements of the array
	a := arg.(*GroupArg)
	count := uint64(0)
	switch t.Kind {
	case ArrayRandLen:
		for count == uint64(len(a.Inner)) {
			count = r.randArrayLen()
		}
	case ArrayRangeLen:
		if t.RangeBegin == t.RangeEnd {
			panic("trying to mutate fixed length array")
		}
		for count == uint64(len(a.Inner)) {
			count = r.randRange(t.RangeBegin, t.RangeEnd)
		}
	}
	if count > uint64(len(a.Inner)) {
		for count > uint64(len(a.Inner)) {
			newArg, newCalls := r.generateArg(s, t.Type)
			a.Inner = append(a.Inner, newArg)
			calls = append(calls, newCalls...)
			for _, c := range newCalls {
				s.analyze(c)
			}
		}
	} else if count < uint64(len(a.Inner)) {
		for _, arg := range a.Inner[count:] {
			removeArg(arg)
		}
		a.Inner = a.Inner[:count]
	}
	return
}

func (t *PtrType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	a := arg.(*PointerArg)
	newArg := r.allocAddr(s, t, a.Res.Size(), a.Res)
	replaceArg(arg, newArg)
	return
}

func (t *StructType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	gen := r.target.SpecialTypes[t.Name()]
	if gen == nil {
		panic("bad arg returned by mutationArgs: StructType")
	}
	var newArg Arg
	newArg, calls = gen(&Gen{r, s}, t, arg)
	a := arg.(*GroupArg)
	for i, f := range newArg.(*GroupArg).Inner {
		replaceArg(a.Inner[i], f)
	}
	return
}

func (t *UnionType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	if gen := r.target.SpecialTypes[t.Name()]; gen != nil {
		var newArg Arg
		newArg, calls = gen(&Gen{r, s}, t, arg)
		replaceArg(arg, newArg)
	} else {
		a := arg.(*UnionArg)
		current := -1
		for i, option := range t.Fields {
			if a.Option.Type().FieldName() == option.FieldName() {
				current = i
				break
			}
		}
		if current == -1 {
			panic("can't find current option in union")
		}
		newIdx := r.Intn(len(t.Fields) - 1)
		if newIdx >= current {
			newIdx++
		}
		optType := t.Fields[newIdx]
		removeArg(a.Option)
		var newOpt Arg
		newOpt, calls = r.generateArg(s, optType)
		replaceArg(arg, MakeUnionArg(t, newOpt))
	}
	return
}

func (t *CsumType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	panic("CsumType can't be mutated")
}

func (t *ConstType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	panic("ConstType can't be mutated")
}

type mutationArgs struct {
	target        *Target
	args          []Arg
	ctxes         []ArgCtx
	ignoreSpecial bool
}

func (ma *mutationArgs) collectArg(arg Arg, ctx *ArgCtx) {
	ignoreSpecial := ma.ignoreSpecial
	ma.ignoreSpecial = false
	switch typ := arg.Type().(type) {
	case *StructType:
		if ma.target.SpecialTypes[typ.Name()] == nil || ignoreSpecial {
			return // For structs only individual fields are updated.
		}
		// These special structs are mutated as a whole.
		ctx.Stop = true
	case *UnionType:
		if ma.target.SpecialTypes[typ.Name()] == nil && len(typ.Fields) == 1 || ignoreSpecial {
			return
		}
		ctx.Stop = true
	case *ArrayType:
		// Don't mutate fixed-size arrays.
		if typ.Kind == ArrayRangeLen && typ.RangeBegin == typ.RangeEnd {
			return
		}
	case *CsumType:
		return // Checksum is updated when the checksummed data changes.
	case *ConstType:
		return // Well, this is const.
	case *BufferType:
		if typ.Kind == BufferString && len(typ.Values) == 1 {
			return // string const
		}
	case *PtrType:
		if arg.(*PointerArg).IsNull() {
			// TODO: we ought to mutate this, but we don't have code for this yet.
			return
		}
	}
	typ := arg.Type()
	if typ == nil || typ.Dir() == DirOut || !typ.Varlen() && typ.Size() == 0 {
		return
	}
	ma.args = append(ma.args, arg)
	ma.ctxes = append(ma.ctxes, *ctx)
}

func mutateData(r *randGen, data []byte, minLen, maxLen uint64) []byte {
	for stop := false; !stop; stop = stop && r.oneOf(3) {
		f := mutateDataFuncs[r.Intn(len(mutateDataFuncs))]
		data, stop = f(r, data, minLen, maxLen)
	}
	return data
}

const maxInc = 35

var mutateDataFuncs = [...]func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool){
	// TODO(dvyukov): duplicate part of data.
	// Flip bit in byte.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if len(data) == 0 {
			return data, false
		}
		byt := r.Intn(len(data))
		bit := r.Intn(8)
		data[byt] ^= 1 << uint(bit)
		return data, true
	},
	// Insert random bytes.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if len(data) == 0 {
			return data, false
		}
		n := r.Intn(16) + 1
		if r := int(maxLen) - len(data); n > r {
			n = r
		}
		pos := r.Intn(len(data))
		for i := 0; i < n; i++ {
			data = append(data, 0)
		}
		copy(data[pos+n:], data[pos:])
		for i := 0; i < n; i++ {
			data[pos+i] = byte(r.Int31())
		}
		if uint64(len(data)) > maxLen || r.bin() {
			data = data[:len(data)-n] // preserve original length
		}
		return data, true
	},
	// Remove bytes.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if len(data) == 0 {
			return data, false
		}
		n := r.Intn(16) + 1
		if n > len(data) {
			n = len(data)
		}
		pos := 0
		if n < len(data) {
			pos = r.Intn(len(data) - n)
		}
		copy(data[pos:], data[pos+n:])
		data = data[:len(data)-n]
		if uint64(len(data)) < minLen || r.bin() {
			for i := 0; i < n; i++ {
				data = append(data, 0) // preserve original length
			}
		}
		return data, true
	},
	// Append a bunch of bytes.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if uint64(len(data)) >= maxLen {
			return data, false
		}
		const max = 256
		n := max - r.biasedRand(max, 10)
		if r := int(maxLen) - len(data); n > r {
			n = r
		}
		for i := 0; i < n; i++ {
			data = append(data, byte(r.rand(256)))
		}
		return data, true
	},
	// Replace int8/int16/int32/int64 with a random value.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		width := 1 << uint(r.Intn(4))
		if len(data) < width {
			return data, false
		}
		i := r.Intn(len(data) - width + 1)
		storeInt(data[i:], r.Uint64(), width)
		return data, true
	},
	// Add/subtract from an int8/int16/int32/int64.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		width := 1 << uint(r.Intn(4))
		if len(data) < width {
			return data, false
		}
		i := r.Intn(len(data) - width + 1)
		v := loadInt(data[i:], width)
		delta := r.rand(2*maxInc+1) - maxInc
		if delta == 0 {
			delta = 1
		}
		if r.oneOf(10) {
			v = swapInt(v, width)
			v += delta
			v = swapInt(v, width)
		} else {
			v += delta
		}
		storeInt(data[i:], v, width)
		return data, true
	},
	// Set int8/int16/int32/int64 to an interesting value.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		width := 1 << uint(r.Intn(4))
		if len(data) < width {
			return data, false
		}
		i := r.Intn(len(data) - width + 1)
		value := r.randInt()
		if r.oneOf(10) {
			value = swap64(value)
		}
		storeInt(data[i:], value, width)
		return data, true
	},
}

func swap16(v uint16) uint16 {
	v0 := byte(v >> 0)
	v1 := byte(v >> 8)
	v = 0
	v |= uint16(v1) << 0
	v |= uint16(v0) << 8
	return v
}

func swap32(v uint32) uint32 {
	v0 := byte(v >> 0)
	v1 := byte(v >> 8)
	v2 := byte(v >> 16)
	v3 := byte(v >> 24)
	v = 0
	v |= uint32(v3) << 0
	v |= uint32(v2) << 8
	v |= uint32(v1) << 16
	v |= uint32(v0) << 24
	return v
}

func swap64(v uint64) uint64 {
	v0 := byte(v >> 0)
	v1 := byte(v >> 8)
	v2 := byte(v >> 16)
	v3 := byte(v >> 24)
	v4 := byte(v >> 32)
	v5 := byte(v >> 40)
	v6 := byte(v >> 48)
	v7 := byte(v >> 56)
	v = 0
	v |= uint64(v7) << 0
	v |= uint64(v6) << 8
	v |= uint64(v5) << 16
	v |= uint64(v4) << 24
	v |= uint64(v3) << 32
	v |= uint64(v2) << 40
	v |= uint64(v1) << 48
	v |= uint64(v0) << 56
	return v
}

func swapInt(v uint64, size int) uint64 {
	switch size {
	case 1:
		return v
	case 2:
		return uint64(swap16(uint16(v)))
	case 4:
		return uint64(swap32(uint32(v)))
	case 8:
		return swap64(v)
	default:
		panic(fmt.Sprintf("swapInt: bad size %v", size))
	}
}

func loadInt(data []byte, size int) uint64 {
	p := unsafe.Pointer(&data[0])
	switch size {
	case 1:
		return uint64(*(*uint8)(p))
	case 2:
		return uint64(*(*uint16)(p))
	case 4:
		return uint64(*(*uint32)(p))
	case 8:
		return *(*uint64)(p)
	default:
		panic(fmt.Sprintf("loadInt: bad size %v", size))
	}
}

func storeInt(data []byte, v uint64, size int) {
	p := unsafe.Pointer(&data[0])
	switch size {
	case 1:
		*(*uint8)(p) = uint8(v)
	case 2:
		*(*uint16)(p) = uint16(v)
	case 4:
		*(*uint32)(p) = uint32(v)
	case 8:
		*(*uint64)(p) = v
	default:
		panic(fmt.Sprintf("storeInt: bad size %v", size))
	}
}
