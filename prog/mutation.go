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

	retry := false
outer:
	for stop := false; !stop || retry; stop = r.oneOf(3) {
		retry = false
		switch {
		case r.oneOf(5):
			// Not all calls have anything squashable,
			// so this has lower priority in reality.
			complexPtrs := p.complexPtrs()
			if len(complexPtrs) == 0 {
				retry = true
				continue
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
				retry = true
				continue
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
				s := analyze(ct, p, p.Calls[0])
				newArg := r.allocAddr(s, base.Type(), base.Res.Size(), base.Res)
				*base = *newArg
			}
		case r.nOutOf(1, 100):
			// Splice with another prog from corpus.
			if len(corpus) == 0 || len(p.Calls) == 0 {
				retry = true
				continue
			}
			p0 := corpus[r.Intn(len(corpus))]
			p0c := p0.Clone()
			idx := r.Intn(len(p.Calls))
			p.Calls = append(p.Calls[:idx], append(p0c.Calls, p.Calls[idx:]...)...)
			for i := len(p.Calls) - 1; i >= ncalls; i-- {
				p.removeCall(i)
			}
		case r.nOutOf(20, 31):
			// Insert a new call.
			if len(p.Calls) >= ncalls {
				retry = true
				continue
			}
			idx := r.biasedRand(len(p.Calls)+1, 5)
			var c *Call
			if idx < len(p.Calls) {
				c = p.Calls[idx]
			}
			s := analyze(ct, p, c)
			calls := r.generateCall(s, p)
			p.insertBefore(c, calls)
		case r.nOutOf(10, 11):
			// Change args of a call.
			if len(p.Calls) == 0 {
				retry = true
				continue
			}
			c := p.Calls[r.Intn(len(p.Calls))]
			if len(c.Args) == 0 {
				retry = true
				continue
			}
			s := analyze(ct, p, c)
			updateSizes := true
			retryArg := false
			for stop := false; !stop || retryArg; stop = r.oneOf(3) {
				retryArg = false
				ma := &mutationArgs{target: p.Target}
				ForeachArg(c, ma.collectArg)
				if len(ma.args) == 0 {
					retry = true
					continue outer
				}
				idx := r.Intn(len(ma.args))
				arg, ctx := ma.args[idx], ma.ctxes[idx]
				calls, ok := p.Target.mutateArg(r, s, arg, ctx, &updateSizes)
				if !ok {
					retryArg = true
					continue
				}
				p.insertBefore(c, calls)
				if updateSizes {
					p.Target.assignSizesCall(c)
				}
				p.Target.SanitizeCall(c)
			}
		default:
			// Remove a random call.
			if len(p.Calls) == 0 {
				retry = true
				continue
			}
			idx := r.Intn(len(p.Calls))
			p.removeCall(idx)
		}
	}

	for _, c := range p.Calls {
		p.Target.SanitizeCall(c)
	}
	if debug {
		if err := p.validate(); err != nil {
			panic(err)
		}
	}
}

func (target *Target) mutateArg(r *randGen, s *state, arg Arg, ctx ArgCtx, updateSizes *bool) (calls []*Call, ok bool) {
	var baseSize uint64
	if ctx.Base != nil {
		baseSize = ctx.Base.Res.Size()
	}
	switch t := arg.Type().(type) {
	case *IntType, *FlagsType:
		a := arg.(*ConstArg)
		if r.bin() {
			var newArg Arg
			newArg, calls = r.generateArg(s, arg.Type())
			replaceArg(arg, newArg)
		} else {
			switch {
			case r.nOutOf(1, 3):
				a.Val += uint64(r.Intn(4)) + 1
			case r.nOutOf(1, 2):
				a.Val -= uint64(r.Intn(4)) + 1
			default:
				a.Val ^= 1 << uint64(r.Intn(64))
			}
		}
	case *LenType:
		if !r.mutateSize(arg.(*ConstArg), *ctx.Parent) {
			return nil, false
		}
		*updateSizes = false
	case *ResourceType, *VmaType, *ProcType:
		var newArg Arg
		newArg, calls = r.generateArg(s, arg.Type())
		replaceArg(arg, newArg)
	case *BufferType:
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
	case *ArrayType:
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
		// TODO: swap elements of the array
	case *PtrType:
		a := arg.(*PointerArg)
		newArg := r.allocAddr(s, t, a.Res.Size(), a.Res)
		replaceArg(arg, newArg)
	case *StructType:
		gen := target.SpecialTypes[t.Name()]
		if gen == nil {
			panic("bad arg returned by mutationArgs: StructType")
		}
		var newArg Arg
		newArg, calls = gen(&Gen{r, s}, t, arg)
		for i, f := range newArg.(*GroupArg).Inner {
			replaceArg(arg.(*GroupArg).Inner[i], f)
		}
	case *UnionType:
		if gen := target.SpecialTypes[t.Name()]; gen != nil {
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
	case *CsumType:
		panic("bad arg returned by mutationArgs: CsumType")
	case *ConstType:
		panic("bad arg returned by mutationArgs: ConstType")
	default:
		panic(fmt.Sprintf("bad arg returned by mutationArgs: %#v, type=%#v", arg, arg.Type()))
	}

	// Update base pointer if size has increased.
	if base := ctx.Base; base != nil && baseSize < base.Res.Size() {
		newArg := r.allocAddr(s, base.Type(), base.Res.Size(), base.Res)
		*base = *newArg
	}
	for _, c := range calls {
		target.SanitizeCall(c)
	}
	return calls, true
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
	const maxInc = 35
	retry := false
loop:
	for stop := false; !stop || retry; stop = r.oneOf(3) {
		retry = false
		// TODO(dvyukov): duplicate part of data.
		switch r.Intn(7) {
		case 0:
			// Flip bit in byte.
			if len(data) == 0 {
				retry = true
				continue loop
			}
			byt := r.Intn(len(data))
			bit := r.Intn(8)
			data[byt] ^= 1 << uint(bit)
		case 1:
			// Insert random bytes.
			if len(data) == 0 || uint64(len(data)) >= maxLen {
				retry = true
				continue loop
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
			if r.bin() {
				data = data[:len(data)-n] // preserve original length
			}
		case 2:
			// Remove bytes.
			if uint64(len(data)) <= minLen {
				retry = true
				continue loop
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
			if r.bin() {
				for i := 0; i < n; i++ {
					data = append(data, 0) // preserve original length
				}
			}
		case 3:
			// Append a bunch of bytes.
			if uint64(len(data)) >= maxLen {
				retry = true
				continue loop
			}
			const max = 256
			n := max - r.biasedRand(max, 10)
			if r := int(maxLen) - len(data); n > r {
				n = r
			}
			for i := 0; i < n; i++ {
				data = append(data, byte(r.rand(256)))
			}
		case 4:
			// Replace int8/int16/int32/int64 with a random value.
			switch r.Intn(4) {
			case 0: // int8
				if len(data) == 0 {
					retry = true
					continue loop
				}
				data[r.Intn(len(data))] = byte(r.rand(1 << 8))
			case 1: // int16
				if len(data) < 2 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data) - 1)
				p := (*uint16)(unsafe.Pointer(&data[i]))
				*p = uint16(r.rand(1 << 16))
			case 2: // int32
				if len(data) < 4 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data) - 3)
				p := (*uint32)(unsafe.Pointer(&data[i]))
				*p = r.Uint32()
			case 3: // int64
				if len(data) < 8 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data) - 7)
				p := (*uint64)(unsafe.Pointer(&data[i]))
				*p = r.Uint64()
			}
		case 5:
			// Add/subtract from an int8/int16/int32/int64.
			switch r.Intn(4) {
			case 0: // int8
				if len(data) == 0 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data))
				delta := byte(r.rand(2*maxInc+1) - maxInc)
				if delta == 0 {
					delta = 1
				}
				data[i] += delta
			case 1: // int16
				if len(data) < 2 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data) - 1)
				p := (*uint16)(unsafe.Pointer(&data[i]))
				delta := uint16(r.rand(2*maxInc+1) - maxInc)
				if delta == 0 {
					delta = 1
				}
				if r.oneOf(10) {
					*p = swap16(swap16(*p) + delta)
				} else {
					*p += delta
				}
			case 2: // int32
				if len(data) < 4 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data) - 3)
				p := (*uint32)(unsafe.Pointer(&data[i]))
				delta := uint32(r.rand(2*maxInc+1) - maxInc)
				if delta == 0 {
					delta = 1
				}
				if r.oneOf(10) {
					*p = swap32(swap32(*p) + delta)
				} else {
					*p += delta
				}
			case 3: // int64
				if len(data) < 8 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data) - 7)
				p := (*uint64)(unsafe.Pointer(&data[i]))
				delta := r.rand(2*maxInc+1) - maxInc
				if delta == 0 {
					delta = 1
				}
				if r.oneOf(10) {
					*p = swap64(swap64(*p) + delta)
				} else {
					*p += delta
				}
			}
		case 6:
			// Set int8/int16/int32/int64 to an interesting value.
			switch r.Intn(4) {
			case 0: // int8
				if len(data) == 0 {
					retry = true
					continue loop
				}
				data[r.Intn(len(data))] = byte(r.randInt())
			case 1: // int16
				if len(data) < 2 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data) - 1)
				value := uint16(r.randInt())
				if r.oneOf(10) {
					value = swap16(value)
				}
				*(*uint16)(unsafe.Pointer(&data[i])) = value
			case 2: // int32
				if len(data) < 4 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data) - 3)
				value := uint32(r.randInt())
				if r.oneOf(10) {
					value = swap32(value)
				}
				*(*uint32)(unsafe.Pointer(&data[i])) = value
			case 3: // int64
				if len(data) < 8 {
					retry = true
					continue loop
				}
				i := r.Intn(len(data) - 7)
				value := r.randInt()
				if r.oneOf(10) {
					value = swap64(value)
				}
				*(*uint64)(unsafe.Pointer(&data[i])) = value
			}
		default:
			panic("bad")
		}
	}
	return data
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

func swap(v, size uint64) uint64 {
	switch size {
	case 64:
		return swap64(v)
	case 32:
		return uint64(swap32(uint32(v)))
	case 16:
		return uint64(swap16(uint16(v)))
	case 8:
		return v
	default:
		panic(fmt.Sprintf("swap: bad size %v", size))
	}
}
