// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"

	"github.com/google/syzkaller/sys"
)

func (p *Prog) Mutate(rs rand.Source, ncalls int, ct *ChoiceTable) {
	r := newRand(rs)
	for stop := false; !stop; stop = r.bin() {
		r.choose(
			20, func() {
				// Insert a new call.
				if len(p.Calls) >= ncalls {
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
					return
				}
				c := p.Calls[r.Intn(len(p.Calls))]
				if len(c.Args) == 0 {
					return
				}
				s := analyze(ct, p, c)
				for stop := false; !stop; stop = r.bin() {
					args, bases, parents := mutationArgs(c)
					if len(args) == 0 {
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
						replaceArg(p, arg, arg1, calls1)
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
						count := r.rand(6)
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
							removed := arg.Inner[count:]
							arg.Inner = arg.Inner[:count]

							foreachArgArray(&removed, nil, func(arg, _ *Arg, _ *[]*Arg) {
								if arg.Kind == ArgResult {
									if _, ok := arg.Res.Uses[arg]; !ok {
										panic("broken tree")
									}
									delete(arg.Res.Uses, arg)
								}
							})

							for _, arg := range referencedArgs(removed, nil) {
								c1 := arg.Call
								s := analyze(ct, p, c1)
								arg1, _, calls1 := r.generateArg(s, arg.Type, arg.Dir, nil)
								replaceArg(p, arg, arg1, calls1)
							}
						}
						// TODO: swap elements of the array
						size = constArg(count)
					case sys.PtrType:
						// TODO: we don't know size for out args
						size := uintptr(1)
						if arg.Res != nil {
							size = arg.Res.Size(arg.Res.Type)
						}
						arg1, calls1 := r.addr(s, size, arg.Res)
						replaceArg(p, arg, arg1, calls1)
					case sys.StructType:
						ctor := isSpecialStruct(a)
						if ctor == nil {
							panic("bad arg returned by mutationArgs: StructType")
						}
						arg1, calls1 := ctor(r, s)
						for i, f := range arg1.Inner {
							replaceArg(p, arg.Inner[i], f, calls1)
							calls1 = nil
						}
					case sys.UnionType:
						//!!! implement me
					case sys.LenType:
						panic("bad arg returned by mutationArgs: LenType")
					case sys.ConstType, sys.StrConstType:
						panic("bad arg returned by mutationArgs: ConstType")
					default:
						panic(fmt.Sprintf("bad arg returned by mutationArgs: %#v, type=%#v", *arg, arg.Type))
					}

					// Update associated size argument if there is one.
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
					return
				}
				idx := r.Intn(len(p.Calls))
				c := p.Calls[idx]
				copy(p.Calls[idx:], p.Calls[idx+1:])
				p.Calls = p.Calls[:len(p.Calls)-1]

				foreachArg(c, func(arg, _ *Arg, _ *[]*Arg) {
					if arg.Kind == ArgResult {
						if _, ok := arg.Res.Uses[arg]; !ok {
							panic("broken tree")
						}
						delete(arg.Res.Uses, arg)
					}
				})

				for _, arg := range referencedArgs(c.Args, c.Ret) {
					c1 := arg.Call
					s := analyze(ct, p, c1)
					arg1, _, calls1 := r.generateArg(s, arg.Type, arg.Dir, nil)
					replaceArg(p, arg, arg1, calls1)
				}
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
				copy(p.Calls[i:], p.Calls[i+1:])
				p.Calls = p.Calls[:len(p.Calls)-1]

				for _, arg := range referencedArgs(c.Args, c.Ret) {
					arg1 := constArg(arg.Type.Default())
					replaceArg(p, arg, arg1, nil)
				}
				foreachArg(c, func(arg, _ *Arg, _ *[]*Arg) {
					if arg.Kind == ArgResult {
						delete(arg.Res.Uses, arg)
					}
				})

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
				constArg(PROT_READ | PROT_WRITE),
				constArg(MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED),
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
		c := p.Calls[i]
		copy(p.Calls[i:], p.Calls[i+1:])
		p.Calls = p.Calls[:len(p.Calls)-1]
		for _, arg := range referencedArgs(c.Args, c.Ret) {
			arg1 := constArg(arg.Type.Default())
			replaceArg(p, arg, arg1, nil)
		}
		foreachArg(c, func(arg, _ *Arg, _ *[]*Arg) {
			if arg.Kind == ArgResult {
				delete(arg.Res.Uses, arg)
			}
		})
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
		case sys.StructType:
			if isSpecialStruct(typ) == nil {
				// For structs only individual fields are updated.
				return
			}
			// These special structs are mutated as a whole.
		case sys.ArrayType:
			// Don't mutate fixed-size arrays.
			if typ.Len != 0 {
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
			if _, ok := base.Type.(sys.StructType); ok && isSpecialStruct(base.Type) != nil {
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

func mutateData(r *randGen, data []byte) []byte {
	for stop := false; !stop; stop = r.bin() {
		r.choose(
			1, func() {
				data = append(data, byte(r.rand(256)))
			},
			1, func() {
				if len(data) == 0 {
					return
				}
				data[r.Intn(len(data))] = byte(r.rand(256))
			},
			1, func() {
				if len(data) == 0 {
					return
				}
				byt := r.Intn(len(data))
				bit := r.Intn(8)
				data[byt] ^= 1 << uint(bit)
			},
			1, func() {
				if len(data) == 0 {
					return
				}
				i := r.Intn(len(data))
				copy(data[i:], data[i+1:])
				data = data[:len(data)-1]
			},
		)
	}
	return data
}

func replaceArg(p *Prog, arg, arg1 *Arg, calls []*Call) {
	if arg.Kind != ArgConst && arg.Kind != ArgResult && arg.Kind != ArgPointer {
		panic(fmt.Sprintf("replaceArg: bad arg kind %v", arg.Kind))
	}
	if arg1.Kind != ArgConst && arg1.Kind != ArgResult && arg1.Kind != ArgPointer {
		panic(fmt.Sprintf("replaceArg: bad arg1 kind %v", arg1.Kind))
	}
	if arg.Kind == ArgResult {
		delete(arg.Res.Uses, arg)
	}
	for _, c := range calls {
		assignTypeAndDir(c)
		sanitizeCall(c)
	}
	c := arg.Call
	p.insertBefore(c, calls)
	// Somewhat hacky, but safe and preserves references to arg.
	uses := arg.Uses
	*arg = *arg1
	arg.Uses = uses
	if arg.Kind == ArgResult {
		delete(arg.Res.Uses, arg1)
		arg.Res.Uses[arg] = true
	}
	assignTypeAndDir(c)
	sanitizeCall(c)
}
