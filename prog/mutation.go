// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"unsafe"
)

func (p *Prog) Mutate(rs rand.Source, ncalls int, ct *ChoiceTable, corpus []*Prog) {
	r := newRand(p.Target, rs)

	retry := false
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
			for stop := false; !stop; stop = r.oneOf(3) {
				args, bases := p.Target.mutationArgs(c)
				if len(args) == 0 {
					retry = true
					continue
				}
				idx := r.Intn(len(args))
				arg, base := args[idx], bases[idx]
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
						arg1, calls1 := r.generateArg(s, arg.Type())
						p.replaceArg(c, arg, arg1, calls1)
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
				case *ResourceType, *VmaType, *ProcType:
					arg1, calls1 := r.generateArg(s, arg.Type())
					p.replaceArg(c, arg, arg1, calls1)
				case *BufferType:
					a := arg.(*DataArg)
					switch t.Kind {
					case BufferBlobRand, BufferBlobRange:
						var data []byte
						data = append([]byte{}, a.Data...)
						var minLen uint64
						maxLen := ^uint64(0)
						if t.Kind == BufferBlobRange {
							minLen = t.RangeBegin
							maxLen = t.RangeEnd
						}
						a.Data = mutateData(r, data, minLen, maxLen)
					case BufferString:
						if r.bin() {
							minLen, maxLen := uint64(0), ^uint64(0)
							if t.TypeSize != 0 {
								minLen, maxLen = t.TypeSize, t.TypeSize
							}
							a.Data = mutateData(r, append([]byte{}, a.Data...), minLen, maxLen)
						} else {
							a.Data = r.randString(s, t.Values, t.Dir())
						}
					case BufferFilename:
						a.Data = []byte(r.filename(s))
					case BufferText:
						a.Data = r.mutateText(t.Text, a.Data)
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
						var calls []*Call
						for count > uint64(len(a.Inner)) {
							arg1, calls1 := r.generateArg(s, t.Type)
							a.Inner = append(a.Inner, arg1)
							for _, c1 := range calls1 {
								calls = append(calls, c1)
								s.analyze(c1)
							}
						}
						for _, c1 := range calls {
							p.Target.SanitizeCall(c1)
						}
						p.Target.SanitizeCall(c)
						p.insertBefore(c, calls)
					} else if count < uint64(len(a.Inner)) {
						for _, arg := range a.Inner[count:] {
							p.removeArg(c, arg)
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
					arg1, calls1 := r.addr(s, t, size, a.Res)
					p.replaceArg(c, arg, arg1, calls1)
				case *StructType:
					gen := p.Target.SpecialStructs[t.Name()]
					if gen == nil {
						panic("bad arg returned by mutationArgs: StructType")
					}
					arg1, calls1 := gen(&Gen{r, s}, t, arg.(*GroupArg))
					for i, f := range arg1.(*GroupArg).Inner {
						p.replaceArg(c, arg.(*GroupArg).Inner[i], f, calls1)
						calls1 = nil
					}
				case *UnionType:
					a := arg.(*UnionArg)
					optType := t.Fields[r.Intn(len(t.Fields))]
					maxIters := 1000
					for i := 0; optType.FieldName() == a.OptionType.FieldName(); i++ {
						optType = t.Fields[r.Intn(len(t.Fields))]
						if i >= maxIters {
							panic(fmt.Sprintf("couldn't generate a different union option after %v iterations, type: %+v", maxIters, t))
						}
					}
					p.removeArg(c, a.Option)
					opt, calls := r.generateArg(s, optType)
					arg1 := unionArg(t, opt, optType)
					p.replaceArg(c, arg, arg1, calls)
				case *LenType:
					panic("bad arg returned by mutationArgs: LenType")
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
						arg1, calls1 := r.addr(s, b.Type(), b.Res.Size(), b.Res)
						for _, c1 := range calls1 {
							p.Target.SanitizeCall(c1)
						}
						p.insertBefore(c, calls1)
						a1 := arg1.(*PointerArg)
						b.PageIndex = a1.PageIndex
						b.PageOffset = a1.PageOffset
						b.PagesNum = a1.PagesNum
					}
				}

				// Update all len fields.
				p.Target.assignSizesCall(c)
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

// Minimize minimizes program p into an equivalent program using the equivalence
// predicate pred.  It iteratively generates simpler programs and asks pred
// whether it is equal to the orginal program or not. If it is equivalent then
// the simplification attempt is committed and the process continues.
func Minimize(p0 *Prog, callIndex0 int, pred0 func(*Prog, int) bool, crash bool) (*Prog, int) {
	pred := pred0
	if debug {
		pred = func(p *Prog, callIndex int) bool {
			if err := p.validate(); err != nil {
				panic(err)
			}
			return pred0(p, callIndex)
		}
	}
	name0 := ""
	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(p0.Calls) {
			panic("bad call index")
		}
		name0 = p0.Calls[callIndex0].Meta.Name
	}

	// Try to glue all mmap's together.
	s := analyze(nil, p0, nil)
	hi := -1
	lo := -1
	for i := 0; i < maxPages; i++ {
		if s.pages[i] {
			hi = i
			if lo == -1 {
				lo = i
			}
		}
	}
	if hi != -1 {
		p := p0.Clone()
		callIndex := callIndex0
		// Remove all mmaps.
		for i := 0; i < len(p.Calls); i++ {
			c := p.Calls[i]
			if i != callIndex && c.Meta == p.Target.MmapSyscall {
				p.removeCall(i)
				if i < callIndex {
					callIndex--
				}
				i--
			}
		}
		// Prepend uber-mmap.
		mmap := p0.Target.MakeMmap(uint64(lo), uint64(hi-lo)+1)
		p.Calls = append([]*Call{mmap}, p.Calls...)
		if callIndex != -1 {
			callIndex++
		}
		if pred(p, callIndex) {
			p0 = p
			callIndex0 = callIndex
		}
	}

	// Try to remove all calls except the last one one-by-one.
	for i := len(p0.Calls) - 1; i >= 0; i-- {
		if i == callIndex0 {
			continue
		}
		callIndex := callIndex0
		if i < callIndex {
			callIndex--
		}
		p := p0.Clone()
		p.removeCall(i)
		if !pred(p, callIndex) {
			continue
		}
		p0 = p
		callIndex0 = callIndex
	}

	var triedPaths map[string]bool

	var rec func(p *Prog, call *Call, arg Arg, path string) bool
	rec = func(p *Prog, call *Call, arg Arg, path string) bool {
		path += fmt.Sprintf("-%v", arg.Type().FieldName())
		switch typ := arg.Type().(type) {
		case *StructType:
			a := arg.(*GroupArg)
			for _, innerArg := range a.Inner {
				if rec(p, call, innerArg, path) {
					return true
				}
			}
		case *UnionType:
			a := arg.(*UnionArg)
			if rec(p, call, a.Option, path) {
				return true
			}
		case *PtrType:
			// TODO: try to remove optional ptrs
			a, ok := arg.(*PointerArg)
			if !ok {
				// Can also be *ConstArg.
				return false
			}
			if a.Res != nil {
				return rec(p, call, a.Res, path)
			}
		case *ArrayType:
			a := arg.(*GroupArg)
			for i, innerArg := range a.Inner {
				innerPath := fmt.Sprintf("%v-%v", path, i)
				if !triedPaths[innerPath] && !crash {
					if (typ.Kind == ArrayRangeLen && len(a.Inner) > int(typ.RangeBegin)) ||
						(typ.Kind == ArrayRandLen) {
						copy(a.Inner[i:], a.Inner[i+1:])
						a.Inner = a.Inner[:len(a.Inner)-1]
						p.removeArg(call, innerArg)
						p.Target.assignSizesCall(call)

						if pred(p, callIndex0) {
							p0 = p
						} else {
							triedPaths[innerPath] = true
						}

						return true
					}
				}
				if rec(p, call, innerArg, innerPath) {
					return true
				}
			}
		case *IntType, *FlagsType, *ProcType:
			// TODO: try to reset bits in ints
			// TODO: try to set separate flags
			if crash {
				return false
			}
			if triedPaths[path] {
				return false
			}
			triedPaths[path] = true
			a := arg.(*ConstArg)
			if a.Val == typ.Default() {
				return false
			}
			v0 := a.Val
			a.Val = typ.Default()
			if pred(p, callIndex0) {
				p0 = p
				return true
			} else {
				a.Val = v0
			}
		case *ResourceType:
			if crash {
				return false
			}
			if triedPaths[path] {
				return false
			}
			triedPaths[path] = true
			a := arg.(*ResultArg)
			if a.Res == nil {
				return false
			}
			r0 := a.Res
			a.Res = nil
			a.Val = typ.Default()
			if pred(p, callIndex0) {
				p0 = p
				return true
			} else {
				a.Res = r0
				a.Val = 0
			}
		case *BufferType:
			// TODO: try to set individual bytes to 0
			if triedPaths[path] {
				return false
			}
			triedPaths[path] = true
			if typ.Kind != BufferBlobRand && typ.Kind != BufferBlobRange {
				return false
			}
			a := arg.(*DataArg)
			minLen := int(typ.RangeBegin)
			for step := len(a.Data) - minLen; len(a.Data) > minLen && step > 0; {
				if len(a.Data)-step >= minLen {
					a.Data = a.Data[:len(a.Data)-step]
					p.Target.assignSizesCall(call)
					if pred(p, callIndex0) {
						continue
					}
					a.Data = a.Data[:len(a.Data)+step]
					p.Target.assignSizesCall(call)
				}
				step /= 2
				if crash {
					break
				}
			}
			p0 = p
		case *VmaType, *LenType, *CsumType, *ConstType:
			// TODO: try to remove offset from vma
			return false
		default:
			panic(fmt.Sprintf("unknown arg type '%+v'", typ))
		}
		return false
	}

	// Try to minimize individual args.
	for i := 0; i < len(p0.Calls); i++ {
		triedPaths = make(map[string]bool)
	again:
		p := p0.Clone()
		call := p.Calls[i]
		for j, arg := range call.Args {
			if rec(p, call, arg, fmt.Sprintf("%v", j)) {
				goto again
			}
		}
	}

	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(p0.Calls) || name0 != p0.Calls[callIndex0].Meta.Name {
			panic(fmt.Sprintf("bad call index after minimization: ncalls=%v index=%v call=%v/%v",
				len(p0.Calls), callIndex0, name0, p0.Calls[callIndex0].Meta.Name))
		}
	}
	return p0, callIndex0
}

func (p *Prog) TrimAfter(idx int) {
	if idx < 0 || idx >= len(p.Calls) {
		panic("trimming non-existing call")
	}
	for i := len(p.Calls) - 1; i > idx; i-- {
		c := p.Calls[i]
		foreachArg(c, func(arg, _ Arg, _ *[]Arg) {
			if a, ok := arg.(*ResultArg); ok && a.Res != nil {
				if used, ok := a.Res.(ArgUsed); ok {
					delete(*used.Used(), arg)
				}
			}
		})
	}
	p.Calls = p.Calls[:idx+1]
}

func (target *Target) mutationArgs(c *Call) (args, bases []Arg) {
	foreachArg(c, func(arg, base Arg, _ *[]Arg) {
		switch typ := arg.Type().(type) {
		case *StructType:
			if target.SpecialStructs[typ.Name()] == nil {
				// For structs only individual fields are updated.
				return
			}
			// These special structs are mutated as a whole.
		case *ArrayType:
			// Don't mutate fixed-size arrays.
			if typ.Kind == ArrayRangeLen && typ.RangeBegin == typ.RangeEnd {
				return
			}
		case *LenType:
			// Size is updated when the size-of arg change.
			return
		case *CsumType:
			// Checksum is updated when the checksummed data changes.
			return
		case *ConstType:
			// Well, this is const.
			return
		case *BufferType:
			if typ.Kind == BufferString && len(typ.Values) == 1 {
				return // string const
			}
		}
		if arg.Type().Dir() == DirOut {
			return
		}
		if base != nil {
			if _, ok := base.Type().(*StructType); ok &&
				target.SpecialStructs[base.Type().Name()] != nil {
				// These special structs are mutated as a whole.
				return
			}
		}
		args = append(args, arg)
		bases = append(bases, base)
	})
	return
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

func mutateData(r *randGen, data []byte, minLen, maxLen uint64) []byte {
	const maxInc = 35
	retry := false
loop:
	for stop := false; !stop || retry; stop = r.oneOf(3) {
		retry = false
		switch r.Intn(13) {
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
		default:
			panic("bad")
		}
	}
	return data
}
