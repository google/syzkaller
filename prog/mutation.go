// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math"
	"math/rand"
	"unsafe"

	"github.com/google/syzkaller/sys"
)

func (p *Prog) Mutate(rs rand.Source, ncalls int, ct *ChoiceTable, corpus []*Prog) {
	r := newRand(rs)

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
			if len(p.Calls) > ncalls {
				p.Calls = p.Calls[:ncalls]
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
			for stop := false; !stop; stop = r.oneOf(3) {
				args, bases := mutationArgs(c)
				if len(args) == 0 {
					retry = true
					continue
				}
				idx := r.Intn(len(args))
				arg, base := args[idx], bases[idx]
				var baseSize uintptr
				if base != nil {
					if base.Kind != ArgPointer || base.Res == nil {
						panic("bad base arg")
					}
					baseSize = base.Res.Size()
				}
				switch a := arg.Type.(type) {
				case *sys.IntType, *sys.FlagsType:
					if r.bin() {
						arg1, calls1 := r.generateArg(s, arg.Type)
						p.replaceArg(c, arg, arg1, calls1)
					} else {
						switch {
						case r.nOutOf(1, 3):
							arg.Val += uintptr(r.Intn(4)) + 1
						case r.nOutOf(1, 2):
							arg.Val -= uintptr(r.Intn(4)) + 1
						default:
							arg.Val ^= 1 << uintptr(r.Intn(64))
						}
					}
				case *sys.ResourceType, *sys.VmaType, *sys.ProcType:
					arg1, calls1 := r.generateArg(s, arg.Type)
					p.replaceArg(c, arg, arg1, calls1)
				case *sys.BufferType:
					switch a.Kind {
					case sys.BufferBlobRand, sys.BufferBlobRange:
						var data []byte
						switch arg.Kind {
						case ArgData:
							data = append([]byte{}, arg.Data...)
						case ArgConst:
							// 0 is OK for optional args.
							if arg.Val != 0 {
								panic(fmt.Sprintf("BufferType has non-zero const value: %v", arg.Val))
							}
						default:
							panic(fmt.Sprintf("bad arg kind for BufferType: %v", arg.Kind))
						}
						minLen := int(0)
						maxLen := math.MaxInt32
						if a.Kind == sys.BufferBlobRange {
							minLen = int(a.RangeBegin)
							maxLen = int(a.RangeEnd)
						}
						arg.Data = mutateData(r, data, minLen, maxLen)
					case sys.BufferString:
						if r.bin() {
							minLen := int(0)
							maxLen := math.MaxInt32
							if a.Length != 0 {
								minLen = int(a.Length)
								maxLen = int(a.Length)
							}
							arg.Data = mutateData(r, append([]byte{}, arg.Data...), minLen, maxLen)
						} else {
							arg.Data = r.randString(s, a.Values, a.Dir())
						}
					case sys.BufferFilename:
						arg.Data = []byte(r.filename(s))
					case sys.BufferText:
						arg.Data = r.mutateText(a.Text, arg.Data)
					default:
						panic("unknown buffer kind")
					}
				case *sys.ArrayType:
					count := uintptr(0)
					switch a.Kind {
					case sys.ArrayRandLen:
						for count == uintptr(len(arg.Inner)) {
							count = r.randArrayLen()
						}
					case sys.ArrayRangeLen:
						if a.RangeBegin == a.RangeEnd {
							panic("trying to mutate fixed length array")
						}
						for count == uintptr(len(arg.Inner)) {
							count = r.randRange(int(a.RangeBegin), int(a.RangeEnd))
						}
					}
					if count > uintptr(len(arg.Inner)) {
						var calls []*Call
						for count > uintptr(len(arg.Inner)) {
							arg1, calls1 := r.generateArg(s, a.Type)
							arg.Inner = append(arg.Inner, arg1)
							for _, c1 := range calls1 {
								calls = append(calls, c1)
								s.analyze(c1)
							}
						}
						for _, c1 := range calls {
							sanitizeCall(c1)
						}
						sanitizeCall(c)
						p.insertBefore(c, calls)
					} else if count < uintptr(len(arg.Inner)) {
						for _, arg := range arg.Inner[count:] {
							p.removeArg(c, arg)
						}
						arg.Inner = arg.Inner[:count]
					}
					// TODO: swap elements of the array
				case *sys.PtrType:
					// TODO: we don't know size for out args
					size := uintptr(1)
					if arg.Res != nil {
						size = arg.Res.Size()
					}
					arg1, calls1 := r.addr(s, a, size, arg.Res)
					p.replaceArg(c, arg, arg1, calls1)
				case *sys.StructType:
					ctor := isSpecialStruct(a)
					if ctor == nil {
						panic("bad arg returned by mutationArgs: StructType")
					}
					arg1, calls1 := ctor(r, s)
					for i, f := range arg1.Inner {
						p.replaceArg(c, arg.Inner[i], f, calls1)
						calls1 = nil
					}
				case *sys.UnionType:
					optType := a.Options[r.Intn(len(a.Options))]
					maxIters := 1000
					for i := 0; optType.FieldName() == arg.OptionType.FieldName(); i++ {
						optType = a.Options[r.Intn(len(a.Options))]
						if i >= maxIters {
							panic(fmt.Sprintf("couldn't generate a different union option after %v iterations, type: %+v", maxIters, a))
						}
					}
					p.removeArg(c, arg.Option)
					opt, calls := r.generateArg(s, optType)
					arg1 := unionArg(a, opt, optType)
					p.replaceArg(c, arg, arg1, calls)
				case *sys.LenType:
					panic("bad arg returned by mutationArgs: LenType")
				case *sys.CsumType:
					panic("bad arg returned by mutationArgs: CsumType")
				case *sys.ConstType:
					panic("bad arg returned by mutationArgs: ConstType")
				default:
					panic(fmt.Sprintf("bad arg returned by mutationArgs: %#v, type=%#v", *arg, arg.Type))
				}

				// Update base pointer if size has increased.
				if base != nil && baseSize < base.Res.Size() {
					arg1, calls1 := r.addr(s, base.Type, base.Res.Size(), base.Res)
					for _, c1 := range calls1 {
						sanitizeCall(c1)
					}
					p.insertBefore(c, calls1)
					arg.AddrPage = arg1.AddrPage
					arg.AddrOffset = arg1.AddrOffset
					arg.AddrPagesNum = arg1.AddrPagesNum
				}

				// Update all len fields.
				assignSizesCall(c)
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
		sanitizeCall(c)
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
func Minimize(p0 *Prog, callIndex0 int, pred func(*Prog, int) bool, crash bool) (*Prog, int) {
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
	for i := 0; i < maxPages; i++ {
		if s.pages[i] {
			hi = i
		}
	}
	if hi != -1 {
		p := p0.Clone()
		callIndex := callIndex0
		// Remove all mmaps.
		for i := 0; i < len(p.Calls); i++ {
			c := p.Calls[i]
			if i != callIndex && c.Meta.Name == "mmap" {
				p.removeCall(i)
				if i < callIndex {
					callIndex--
				}
				i--
			}
		}
		// Prepend uber-mmap.
		mmap := createMmapCall(0, uintptr(hi)+1)
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

	var rec func(p *Prog, call *Call, arg *Arg, path string) bool
	rec = func(p *Prog, call *Call, arg *Arg, path string) bool {
		path += fmt.Sprintf("-%v", arg.Type.FieldName())
		switch typ := arg.Type.(type) {
		case *sys.StructType:
			for _, innerArg := range arg.Inner {
				if rec(p, call, innerArg, path) {
					return true
				}
			}
		case *sys.UnionType:
			if rec(p, call, arg.Option, path) {
				return true
			}
		case *sys.PtrType:
			// TODO: try to remove optional ptrs
			if arg.Res != nil {
				return rec(p, call, arg.Res, path)
			}
		case *sys.ArrayType:
			for i, innerArg := range arg.Inner {
				innerPath := fmt.Sprintf("%v-%v", path, i)
				if !triedPaths[innerPath] && !crash {
					if (typ.Kind == sys.ArrayRangeLen && len(arg.Inner) > int(typ.RangeBegin)) ||
						(typ.Kind == sys.ArrayRandLen) {
						copy(arg.Inner[i:], arg.Inner[i+1:])
						arg.Inner = arg.Inner[:len(arg.Inner)-1]
						p.removeArg(call, innerArg)
						assignSizesCall(call)

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
		case *sys.IntType, *sys.FlagsType, *sys.ResourceType, *sys.ProcType:
			// TODO: try to reset bits in ints
			// TODO: try to set separate flags
			if crash {
				return false
			}
			if triedPaths[path] {
				return false
			}
			triedPaths[path] = true
			if arg.Val == typ.Default() {
				return false
			}
			v0 := arg.Val
			arg.Val = typ.Default()
			if pred(p, callIndex0) {
				p0 = p
				return true
			} else {
				arg.Val = v0
			}
		case *sys.BufferType:
			// TODO: try to set individual bytes to 0
			if triedPaths[path] {
				return false
			}
			triedPaths[path] = true
			if typ.Kind != sys.BufferBlobRand && typ.Kind != sys.BufferBlobRange {
				return false
			}
			minLen := int(typ.RangeBegin)
			for step := len(arg.Data) - minLen; len(arg.Data) > minLen && step > 0; {
				if len(arg.Data)-step >= minLen {
					arg.Data = arg.Data[:len(arg.Data)-step]
					assignSizesCall(call)
					if pred(p, callIndex0) {
						continue
					}
					arg.Data = arg.Data[:len(arg.Data)+step]
					assignSizesCall(call)
				}
				step /= 2
				if crash {
					break
				}
			}
			p0 = p
		case *sys.VmaType, *sys.LenType, *sys.CsumType, *sys.ConstType:
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
			panic(fmt.Sprintf("bad call index after minimizatoin: ncalls=%v index=%v call=%v/%v",
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
		foreachArg(c, func(arg, _ *Arg, _ *[]*Arg) {
			if arg.Kind == ArgResult {
				delete(arg.Res.Uses, arg)
			}
		})
	}
	p.Calls = p.Calls[:idx+1]
}

func mutationArgs(c *Call) (args, bases []*Arg) {
	foreachArg(c, func(arg, base *Arg, _ *[]*Arg) {
		switch typ := arg.Type.(type) {
		case *sys.StructType:
			if isSpecialStruct(typ) == nil {
				// For structs only individual fields are updated.
				return
			}
			// These special structs are mutated as a whole.
		case *sys.ArrayType:
			// Don't mutate fixed-size arrays.
			if typ.Kind == sys.ArrayRangeLen && typ.RangeBegin == typ.RangeEnd {
				return
			}
		case *sys.LenType:
			// Size is updated when the size-of arg change.
			return
		case *sys.CsumType:
			// Checksum is updated when the checksummed data changes.
			return
		case *sys.ConstType:
			// Well, this is const.
			return
		case *sys.BufferType:
			if typ.Kind == sys.BufferString && len(typ.Values) == 1 {
				return // string const
			}
		}
		if arg.Type.Dir() == sys.DirOut {
			return
		}
		if base != nil {
			if _, ok := base.Type.(*sys.StructType); ok && isSpecialStruct(base.Type) != nil {
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

func mutateData(r *randGen, data []byte, minLen, maxLen int) []byte {
	const maxInc = 35
	retry := false
loop:
	for stop := false; !stop || retry; stop = r.oneOf(3) {
		retry = false
		switch r.Intn(13) {
		case 0:
			// Append byte.
			if len(data) >= maxLen {
				retry = true
				continue loop
			}
			data = append(data, byte(r.rand(256)))
		case 1:
			// Remove byte.
			if len(data) == 0 || len(data) <= minLen {
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
			delta := uint64(r.rand(2*maxInc+1) - maxInc)
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
			value := uint64(r.randInt())
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
