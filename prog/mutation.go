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
			// Mutating mmap() arguments almost certainly doesn't give us new coverage.
			if c.Meta == p.Target.MmapSyscall && r.nOutOf(99, 100) {
				retry = true
				continue
			}
			s := analyze(ct, p, c)
			updateSizes := true
			retryArg := false
			for stop := false; !stop || retryArg; stop = r.oneOf(3) {
				retryArg = false
				args, bases, parents := p.Target.mutationArgs(c)
				if len(args) == 0 {
					retry = true
					continue outer
				}
				idx := r.Intn(len(args))
				arg, base, parent := args[idx], bases[idx], parents[idx]
				calls, ok := p.Target.mutateArg(r, s, arg, base, parent, &updateSizes)
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

func (target *Target) mutateArg(r *randGen, s *state, arg, base Arg, parent *[]Arg, updateSizes *bool) (calls []*Call, ok bool) {
	var baseSize uint64
	if base != nil {
		b, ok := base.(*PointerArg)
		if !ok || b.Res == nil {
			panic("bad base arg")
		}
		baseSize = b.Res.Size()
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
		if !r.mutateSize(arg.(*ConstArg), *parent) {
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
			a.data = []byte(r.filename(s))
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
		a, ok := arg.(*PointerArg)
		if !ok {
			break
		}
		// TODO: we don't know size for out args
		size := uint64(1)
		if a.Res != nil {
			size = a.Res.Size()
		}
		var newArg Arg
		newArg, calls = r.addr(s, t, size, a.Res)
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
	if base != nil {
		b := base.(*PointerArg)
		if baseSize < b.Res.Size() {
			newArg, newCalls := r.addr(s, b.Type(), b.Res.Size(), b.Res)
			calls = append(calls, newCalls...)
			a1 := newArg.(*PointerArg)
			b.PageIndex = a1.PageIndex
			b.PageOffset = a1.PageOffset
			b.PagesNum = a1.PagesNum
		}
	}
	for _, c := range calls {
		target.SanitizeCall(c)
	}
	return calls, true
}

func (target *Target) mutationSubargs(arg0 Arg) (args, bases []Arg, parents []*[]Arg) {
	ForeachSubarg(arg0, func(arg, base Arg, parent *[]Arg) {
		if target.needMutateArg(arg, base, parent) {
			args = append(args, arg)
			bases = append(bases, base)
			parents = append(parents, parent)
		}
	})
	return
}

func (target *Target) mutationArgs(c *Call) (args, bases []Arg, parents []*[]Arg) {
	foreachArg(c, func(arg, base Arg, parent *[]Arg) {
		if target.needMutateArg(arg, base, parent) {
			args = append(args, arg)
			bases = append(bases, base)
			parents = append(parents, parent)
		}
	})
	return
}

func (target *Target) needMutateArg(arg, base Arg, parent *[]Arg) bool {
	switch typ := arg.Type().(type) {
	case *StructType:
		if target.SpecialTypes[typ.Name()] == nil {
			// For structs only individual fields are updated.
			return false
		}
		// These special structs are mutated as a whole.
	case *UnionType:
		if target.SpecialTypes[typ.Name()] == nil && len(typ.Fields) == 1 {
			return false
		}
	case *ArrayType:
		// Don't mutate fixed-size arrays.
		if typ.Kind == ArrayRangeLen && typ.RangeBegin == typ.RangeEnd {
			return false
		}
	case *CsumType:
		// Checksum is updated when the checksummed data changes.
		return false
	case *ConstType:
		// Well, this is const.
		return false
	case *BufferType:
		if typ.Kind == BufferString && len(typ.Values) == 1 {
			return false // string const
		}
	}
	typ := arg.Type()
	if typ.Dir() == DirOut || !typ.Varlen() && typ.Size() == 0 {
		return false
	}
	if base != nil {
		// TODO(dvyukov): need to check parent as well.
		// Say, timespec can be part of another struct and base
		// will point to that other struct, not timespec.
		// Strictly saying, we need to check parents all way up,
		// or better bail out from recursion when we reach
		// a special struct.
		_, isStruct := base.Type().(*StructType)
		_, isUnion := base.Type().(*UnionType)
		if (isStruct || isUnion) &&
			target.SpecialTypes[base.Type().Name()] != nil {
			// These special structs/unions are mutated as a whole.
			return false
		}
	}
	return true
}

func mutateData(r *randGen, data []byte, minLen, maxLen uint64) []byte {
	const maxInc = 35
	retry := false
loop:
	for stop := false; !stop || retry; stop = r.oneOf(3) {
		retry = false
		switch r.Intn(14) {
		case 0:
			// Append byte.
			if uint64(len(data)) >= maxLen {
				retry = true
				continue loop
			}
			data = append(data, byte(r.rand(256)))
		case 1:
			// Remove byte.
			if len(data) == 0 || uint64(len(data)) <= minLen {
				retry = true
				continue loop
			}
			i := r.Intn(len(data))
			copy(data[i:], data[i+1:])
			data = data[:len(data)-1]
		case 2:
			// Replace byte with random value.
			if len(data) == 0 {
				retry = true
				continue loop
			}
			data[r.Intn(len(data))] = byte(r.rand(256))
		case 3:
			// Flip bit in byte.
			if len(data) == 0 {
				retry = true
				continue loop
			}
			byt := r.Intn(len(data))
			bit := r.Intn(8)
			data[byt] ^= 1 << uint(bit)
		case 4:
			// Swap two bytes.
			if len(data) < 2 {
				retry = true
				continue loop
			}
			i1 := r.Intn(len(data))
			i2 := r.Intn(len(data))
			data[i1], data[i2] = data[i2], data[i1]
		case 5:
			// Add / subtract from a byte.
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
		case 6:
			// Add / subtract from a uint16.
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
			if r.bin() {
				*p += delta
			} else {
				*p = swap16(swap16(*p) + delta)
			}
		case 7:
			// Add / subtract from a uint32.
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
			if r.bin() {
				*p += delta
			} else {
				*p = swap32(swap32(*p) + delta)
			}
		case 8:
			// Add / subtract from a uint64.
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
			if r.bin() {
				*p += delta
			} else {
				*p = swap64(swap64(*p) + delta)
			}
		case 9:
			// Set byte to an interesting value.
			if len(data) == 0 {
				retry = true
				continue loop
			}
			data[r.Intn(len(data))] = byte(r.randInt())
		case 10:
			// Set uint16 to an interesting value.
			if len(data) < 2 {
				retry = true
				continue loop
			}
			i := r.Intn(len(data) - 1)
			value := uint16(r.randInt())
			if r.bin() {
				value = swap16(value)
			}
			*(*uint16)(unsafe.Pointer(&data[i])) = value
		case 11:
			// Set uint32 to an interesting value.
			if len(data) < 4 {
				retry = true
				continue loop
			}
			i := r.Intn(len(data) - 3)
			value := uint32(r.randInt())
			if r.bin() {
				value = swap32(value)
			}
			*(*uint32)(unsafe.Pointer(&data[i])) = value
		case 12:
			// Set uint64 to an interesting value.
			if len(data) < 8 {
				retry = true
				continue loop
			}
			i := r.Intn(len(data) - 7)
			value := r.randInt()
			if r.bin() {
				value = swap64(value)
			}
			*(*uint64)(unsafe.Pointer(&data[i])) = value
		case 13:
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
