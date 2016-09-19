// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"unsafe"

	"github.com/google/syzkaller/sys"
)

func (p *Prog) Mutate(rs rand.Source, ncalls int, ct *ChoiceTable) {
	r := newRand(rs)
	retry := false
	for stop := false; !stop || retry; stop = r.bin() {
		retry = false
		r.choose(
			20, func() {
				// Insert a new call.
				if len(p.Calls) >= ncalls {
					retry = true
					return
				}
				idx := r.biasedRand(len(p.Calls)+1, 5)
				var c *Call
				if idx < len(p.Calls) {
					c = p.Calls[idx]
				}
				s := analyze(ct, p, c)
				calls := r.generateCall(s, p)
				p.insertBefore(c, calls)
			},
			10, func() {
				// Change args of a call.
				if len(p.Calls) == 0 {
					retry = true
					return
				}
				c := p.Calls[r.Intn(len(p.Calls))]
				if len(c.Args) == 0 {
					retry = true
					return
				}
				s := analyze(ct, p, c)
				for stop := false; !stop; stop = r.bin() {
					args, bases, parents := mutationArgs(c)
					if len(args) == 0 {
						retry = true
						return
					}
					idx := r.Intn(len(args))
					arg, base, parent := args[idx], bases[idx], parents[idx]
					var baseSize uintptr
					if base != nil {
						if base.Kind != ArgPointer || base.Res == nil {
							panic("bad base arg")
						}
						baseSize = base.Res.Size(base.Res.Type)
					}
					var size *Arg
					switch a := arg.Type.(type) {
					case sys.IntType, sys.FlagsType, sys.FileoffType, sys.ResourceType, sys.VmaType:
						arg1, size1, calls1 := r.generateArg(s, arg.Type, arg.Dir, nil)
						p.replaceArg(arg, arg1, calls1)
						size = size1
					case sys.BufferType:
						switch a.Kind {
						case sys.BufferBlob:
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
							arg.Data = mutateData(r, data)
						case sys.BufferString:
							if r.bin() {
								arg.Data = mutateData(r, append([]byte{}, arg.Data...))
							} else {
								arg.Data = r.randString(s)
							}
						case sys.BufferFilesystem:
							arg.Data = r.filesystem(s)
						case sys.BufferSockaddr:
							arg.Data = r.sockaddr(s)
						case sys.BufferAlgType:
							arg.Data = r.algType(s)
						case sys.BufferAlgName:
							arg.Data = r.algName(s)
						default:
							panic("unknown buffer kind")
						}
						size = constArg(uintptr(len(arg.Data)))
					case sys.FilenameType:
						filename := r.filename(s)
						arg.Data = []byte(filename)
					case sys.ArrayType:
						count := uintptr(0)
						switch a.Kind {
						case sys.ArrayRandLen:
							for count == uintptr(len(arg.Inner)) {
								count = r.rand(6)
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
								arg1, _, calls1 := r.generateArg(s, a.Type, arg.Dir, nil)
								arg.Inner = append(arg.Inner, arg1)
								for _, c1 := range calls1 {
									calls = append(calls, c1)
									s.analyze(c1)
								}
							}
							for _, c1 := range calls {
								assignTypeAndDir(c1)
								sanitizeCall(c1)
							}
							assignTypeAndDir(c)
							sanitizeCall(c)
							p.insertBefore(c, calls)
						} else if count < uintptr(len(arg.Inner)) {
							for _, arg := range arg.Inner[count:] {
								p.removeArg(arg)
							}
							arg.Inner = arg.Inner[:count]
						}
						// TODO: swap elements of the array
						size = constArg(count)
						for _, elem := range arg.Inner {
							size.ByteSize += elem.Size(a.Type)
						}
					case sys.PtrType:
						// TODO: we don't know size for out args
						size := uintptr(1)
						if arg.Res != nil {
							size = arg.Res.Size(arg.Res.Type)
						}
						arg1, calls1 := r.addr(s, size, arg.Res)
						p.replaceArg(arg, arg1, calls1)
					case *sys.StructType:
						ctor := isSpecialStruct(a)
						if ctor == nil {
							panic("bad arg returned by mutationArgs: StructType")
						}
						arg1, calls1 := ctor(r, s)
						for i, f := range arg1.Inner {
							p.replaceArg(arg.Inner[i], f, calls1)
							calls1 = nil
						}
					case *sys.UnionType:
						optType := a.Options[r.Intn(len(a.Options))]
						for optType.Name() == arg.OptionType.Name() {
							optType = a.Options[r.Intn(len(a.Options))]
						}
						p.removeArg(arg.Option)
						opt, size1, calls := r.generateArg(s, optType, arg.Dir, nil)
						arg1 := unionArg(opt, optType)
						p.replaceArg(arg, arg1, calls)
						size = size1
					case sys.LenType:
						panic("bad arg returned by mutationArgs: LenType")
					case sys.ConstType, sys.StrConstType:
						panic("bad arg returned by mutationArgs: ConstType")
					default:
						panic(fmt.Sprintf("bad arg returned by mutationArgs: %#v, type=%#v", *arg, arg.Type))
					}

					// Update associated size argument if there is one.
					// TODO: update parent size.
					if size != nil {
						name := arg.Type.Name()
						if name == "" && base != nil {
							name = base.Type.Name()
						}
						for _, arg1 := range *parent {
							if sz, ok := arg1.Type.(sys.LenType); ok && sz.Buf == name {
								if arg1.Kind != ArgConst && arg1.Kind != ArgPageSize {
									panic(fmt.Sprintf("size arg is not const: %#v", *arg1))
								}
								arg1.Val = size.Val
								if sz.ByteSize {
									if size.Val != 0 && size.ByteSize == 0 {
										panic(fmt.Sprintf("no byte size for %v in %v: size=%v", name, c.Meta.Name, size.Val))
									}
									arg1.Val = size.ByteSize
								}
								arg1.AddrPage = size.AddrPage
								arg1.AddrOffset = size.AddrOffset
							}
						}
					}

					// Update base pointer if size has increased.
					if base != nil && baseSize < base.Res.Size(base.Res.Type) {
						arg1, calls1 := r.addr(s, base.Res.Size(base.Res.Type), base.Res)
						for _, c := range calls1 {
							assignTypeAndDir(c)
							sanitizeCall(c)
						}
						p.insertBefore(c, calls1)
						arg.AddrPage = arg1.AddrPage
						arg.AddrOffset = arg1.AddrOffset
					}
				}
			},
			1, func() {
				// Remove a random call.
				if len(p.Calls) == 0 {
					retry = true
					return
				}
				idx := r.Intn(len(p.Calls))
				p.removeCall(idx)
			},
		)
	}
	for _, c := range p.Calls {
		assignTypeAndDir(c)
		sanitizeCall(c)
	}
	if err := p.validate(); err != nil {
		panic(err)
	}
}

// Minimize minimizes program p into an equivalent program using the equivalence
// predicate pred.  It iteratively generates simpler programs and asks pred
// whether it is equal to the orginal program or not. If it is equivalent then
// the simplification attempt is committed and the process continues.
func Minimize(p0 *Prog, callIndex0 int, pred func(*Prog, int) bool) (*Prog, int) {
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
		mmap := &Call{
			Meta: sys.CallMap["mmap"],
			Args: []*Arg{
				pointerArg(0, 0, nil),
				pageSizeArg(uintptr(hi)+1, 0),
				constArg(sys.PROT_READ | sys.PROT_WRITE),
				constArg(sys.MAP_ANONYMOUS | sys.MAP_PRIVATE | sys.MAP_FIXED),
				constArg(sys.InvalidFD),
				constArg(0),
			},
		}
		assignTypeAndDir(mmap)
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
	// TODO: simplify individual arguments:
	// - replace constants with 0
	// - reset bits in constants
	// - remove offsets from addresses
	// - replace file descriptors with -1
	// etc
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

func mutationArgs(c *Call) (args, bases []*Arg, parents []*[]*Arg) {
	foreachArg(c, func(arg, base *Arg, parent *[]*Arg) {
		switch typ := arg.Type.(type) {
		case *sys.StructType:
			if isSpecialStruct(typ) == nil {
				// For structs only individual fields are updated.
				return
			}
			// These special structs are mutated as a whole.
		case sys.ArrayType:
			// Don't mutate fixed-size arrays.
			if typ.Kind == sys.ArrayRangeLen && typ.RangeBegin == typ.RangeEnd {
				return
			}
		case sys.LenType:
			// Size is updated when the size-of arg change.
			return
		case sys.ConstType, sys.StrConstType:
			// Well, this is const.
			return
		}
		if arg.Dir == DirOut {
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
		parents = append(parents, parent)
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

func mutateData(r *randGen, data []byte) []byte {
	const maxInc = 35
	for stop := false; !stop; stop = r.bin() {
		r.choose(
			100, func() {
				// Append byte.
				data = append(data, byte(r.rand(256)))
			},
			100, func() {
				// Remove byte.
				if len(data) == 0 {
					return
				}
				i := r.Intn(len(data))
				copy(data[i:], data[i+1:])
				data = data[:len(data)-1]
			},
			100, func() {
				// Replace byte with random value.
				if len(data) == 0 {
					return
				}
				data[r.Intn(len(data))] = byte(r.rand(256))
			},
			100, func() {
				// Flip bit in byte.
				if len(data) == 0 {
					return
				}
				byt := r.Intn(len(data))
				bit := r.Intn(8)
				data[byt] ^= 1 << uint(bit)
			},
			100, func() {
				// Swap two bytes.
				if len(data) < 2 {
					return
				}
				i1 := r.Intn(len(data))
				i2 := r.Intn(len(data))
				data[i1], data[i2] = data[i2], data[i1]
			},
			100, func() {
				// Add / subtract from a byte.
				if len(data) == 0 {
					return
				}
				i := r.Intn(len(data))
				delta := byte(r.rand(2*maxInc+1) - maxInc)
				if delta == 0 {
					delta = 1
				}
				data[i] += delta
			},
			100, func() {
				// Add / subtract from a uint16.
				if len(data) < 2 {
					return
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
			},
			100, func() {
				// Add / subtract from a uint32.
				if len(data) < 4 {
					return
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
			},
			100, func() {
				// Add / subtract from a uint64.
				if len(data) < 8 {
					return
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
			},
			100, func() {
				// Set byte to an interesting value.
				if len(data) == 0 {
					return
				}
				data[r.Intn(len(data))] = byte(r.randInt())
			},
			100, func() {
				// Set uint16 to an interesting value.
				if len(data) < 2 {
					return
				}
				i := r.Intn(len(data) - 1)
				value := uint16(r.randInt())
				if r.bin() {
					value = swap16(value)
				}
				*(*uint16)(unsafe.Pointer(&data[i])) = value
			},
			100, func() {
				// Set uint32 to an interesting value.
				if len(data) < 4 {
					return
				}
				i := r.Intn(len(data) - 3)
				value := uint32(r.randInt())
				if r.bin() {
					value = swap32(value)
				}
				*(*uint32)(unsafe.Pointer(&data[i])) = value
			},
			100, func() {
				// Set uint64 to an interesting value.
				if len(data) < 8 {
					return
				}
				i := r.Intn(len(data) - 7)
				value := uint64(r.randInt())
				if r.bin() {
					value = swap64(value)
				}
				*(*uint64)(unsafe.Pointer(&data[i])) = value
			},
		)
	}
	return data
}
