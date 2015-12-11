// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file does serialization of programs for executor binary.
// The format aims at simple parsing: binary and irreversible.

package prog

const (
	instrEOF = ^uintptr(iota)
	instrCopyin
	instrCopyout
	instrSetPad
	instrCheckPad
)

const (
	execArgConst = uintptr(iota)
	execArgResult
	execArgData
)

const (
	ptrSize    = 8
	pageSize   = 4 << 10
	dataOffset = 512 << 20
)

func (p *Prog) SerializeForExec() []byte {
	if err := p.validate(); err != nil {
		panic("serializing invalid program")
	}
	var instrSeq uintptr
	w := &execContext{args: make(map[*Arg]*argInfo)}
	for _, c := range p.Calls {
		// Calculate arg offsets within structs.
		foreachArg(c, func(arg, base *Arg, _ *[]*Arg) {
			if base == nil || arg.Kind == ArgGroup {
				return
			}
			if w.args[base] == nil {
				w.args[base] = &argInfo{}
			}
			w.args[arg] = &argInfo{Offset: w.args[base].CurSize}
			w.args[base].CurSize += arg.Size(arg.Type)
		})
		// Generate copyin instructions that fill in data into pointer arguments.
		foreachArg(c, func(arg, _ *Arg, _ *[]*Arg) {
			if arg.Kind == ArgPointer && arg.Res != nil {
				var rec func(*Arg)
				rec = func(arg1 *Arg) {
					if arg1.Kind == ArgGroup {
						for _, arg2 := range arg1.Inner {
							rec(arg2)
						}
						return
					}
					if arg1.Kind == ArgData && len(arg1.Data) == 0 {
						return
					}
					pad, padSize := arg1.IsPad()
					if (arg1.Dir == DirIn && !pad) || (arg1.Dir == DirOut && pad) || arg1.Dir == DirInOut {
						if pad {
							w.write(instrSetPad)
							w.write(physicalAddr(arg) + w.args[arg1].Offset)
							w.write(padSize)
						} else {
							w.write(instrCopyin)
							w.write(physicalAddr(arg) + w.args[arg1].Offset)
							w.writeArg(arg1)
						}
						instrSeq++
					}
				}
				rec(arg.Res)
			}
		})
		// Generate the call itself.
		w.write(uintptr(c.Meta.ID))
		w.write(uintptr(len(c.Args)))
		for _, arg := range c.Args {
			w.writeArg(arg)
		}
		w.args[c.Ret] = &argInfo{Idx: instrSeq}
		instrSeq++
		// Generate copyout instructions that persist interesting return values.
		foreachArg(c, func(arg, base *Arg, _ *[]*Arg) {
			pad, padSize := arg.IsPad()
			if pad && arg.Dir != DirIn {
				instrSeq++
				info := w.args[arg]
				w.write(instrCheckPad)
				w.write(physicalAddr(base) + info.Offset)
				w.write(padSize)
				return
			}
			if pad || len(arg.Uses) == 0 {
				return
			}
			switch arg.Kind {
			case ArgReturn:
				// Idx is already assigned above.
			case ArgConst, ArgResult:
				// Create a separate copyout instruction that has own Idx.
				if base.Kind != ArgPointer {
					panic("arg base is not a pointer")
				}
				info := w.args[arg]
				info.Idx = instrSeq
				instrSeq++
				w.write(instrCopyout)
				w.write(physicalAddr(base) + info.Offset)
				w.write(arg.Size(arg.Type))
			default:
				panic("bad arg kind in copyout")
			}
		})
	}
	w.write(instrEOF)
	return w.buf
}

func physicalAddr(arg *Arg) uintptr {
	if arg.Kind != ArgPointer {
		panic("physicalAddr: bad arg kind")
	}
	addr := arg.AddrPage*pageSize + dataOffset
	if arg.AddrOffset >= 0 {
		addr += uintptr(arg.AddrOffset)
	} else {
		addr += pageSize - uintptr(-arg.AddrOffset)
	}
	return addr
}

type execContext struct {
	buf  []byte
	args map[*Arg]*argInfo
}

type argInfo struct {
	Offset  uintptr // from base pointer
	CurSize uintptr
	Idx     uintptr // instruction index
}

func (w *execContext) write(v uintptr) {
	w.buf = append(w.buf, byte(v>>0), byte(v>>8), byte(v>>16), byte(v>>24), byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func (w *execContext) writeArg(arg *Arg) {
	switch arg.Kind {
	case ArgConst:
		w.write(execArgConst)
		w.write(arg.Size(arg.Type))
		w.write(arg.Val)
	case ArgResult:
		w.write(execArgResult)
		w.write(arg.Size(arg.Type))
		w.write(w.args[arg.Res].Idx)
		w.write(arg.OpDiv)
		w.write(arg.OpAdd)
	case ArgPointer:
		w.write(execArgConst)
		w.write(arg.Size(arg.Type))
		w.write(physicalAddr(arg))
	case ArgPageSize:
		w.write(execArgConst)
		w.write(arg.Size(arg.Type))
		w.write(arg.AddrPage * pageSize)
	case ArgData:
		w.write(execArgData)
		w.write(uintptr(len(arg.Data)))
		for i := 0; i < len(arg.Data); i += 8 {
			var v uintptr
			for j := 0; j < 8; j++ {
				if i+j >= len(arg.Data) {
					break
				}
				v |= uintptr(arg.Data[i+j]) << uint(j*8)
			}
			w.write(v)
		}
	case ArgGroup:
		// Squash groups.
		for _, arg1 := range arg.Inner {
			w.writeArg(arg1)
		}
	default:
		panic("unknown arg type")
	}
}
