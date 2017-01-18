// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file does serialization of programs for executor binary.
// The format aims at simple parsing: binary and irreversible.

package prog

import (
	"fmt"

	"github.com/google/syzkaller/sys"
)

const (
	ExecInstrEOF = ^uintptr(iota)
	ExecInstrCopyin
	ExecInstrCopyout
)

const (
	ExecArgConst = uintptr(iota)
	ExecArgResult
	ExecArgData
)

const (
	ptrSize    = 8
	pageSize   = 4 << 10
	dataOffset = 512 << 20
)

func (p *Prog) SerializeForExec(pid int) []byte {
	if err := p.validate(); err != nil {
		panic(fmt.Errorf("serializing invalid program: %v", err))
	}
	var instrSeq uintptr
	w := &execContext{args: make(map[*Arg]*argInfo)}
	for _, c := range p.Calls {
		// Calculate arg offsets within structs.
		// Generate copyin instructions that fill in data into pointer arguments.
		foreachArg(c, func(arg, _ *Arg, _ *[]*Arg) {
			if arg.Kind == ArgPointer && arg.Res != nil {
				var rec func(*Arg, uintptr) uintptr
				rec = func(arg1 *Arg, offset uintptr) uintptr {
					w.args[arg1] = &argInfo{Offset: offset}
					if arg1.Kind == ArgGroup {
						var totalSize uintptr
						for _, arg2 := range arg1.Inner {
							size := rec(arg2, offset)
							if arg2.Type.BitfieldLength() == 0 || arg2.Type.BitfieldLast() {
								offset += size
								totalSize += size
							}
						}
						if totalSize > arg1.Size() {
							panic(fmt.Sprintf("bad group arg size %v, should be <= %v for %+v", totalSize, arg1.Size(), arg1))
						}
						return arg1.Size()
					}
					if arg1.Kind == ArgUnion {
						size := rec(arg1.Option, offset)
						offset += size
						if size > arg1.Size() {
							panic(fmt.Sprintf("bad union arg size %v, should be <= %v for %+v", size, arg1.Size(), arg1))
						}
						return arg1.Size()
					}
					if !sys.IsPad(arg1.Type) &&
						!(arg1.Kind == ArgData && len(arg1.Data) == 0) &&
						arg1.Type.Dir() != sys.DirOut {
						w.write(ExecInstrCopyin)
						w.write(physicalAddr(arg) + offset)
						w.writeArg(arg1, pid)
						instrSeq++
					}
					return arg1.Size()
				}
				rec(arg.Res, 0)
			}
		})
		// Generate the call itself.
		w.write(uintptr(c.Meta.ID))
		w.write(uintptr(len(c.Args)))
		for _, arg := range c.Args {
			w.writeArg(arg, pid)
		}
		w.args[c.Ret] = &argInfo{Idx: instrSeq}
		instrSeq++
		// Generate copyout instructions that persist interesting return values.
		foreachArg(c, func(arg, base *Arg, _ *[]*Arg) {
			if len(arg.Uses) == 0 {
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
				w.write(ExecInstrCopyout)
				w.write(physicalAddr(base) + info.Offset)
				w.write(arg.Size())
			default:
				panic("bad arg kind in copyout")
			}
		})
	}
	w.write(ExecInstrEOF)
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
	Offset uintptr // from base pointer
	Idx    uintptr // instruction index
}

func (w *execContext) write(v uintptr) {
	w.buf = append(w.buf, byte(v>>0), byte(v>>8), byte(v>>16), byte(v>>24), byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func (w *execContext) writeArg(arg *Arg, pid int) {
	switch arg.Kind {
	case ArgConst:
		w.write(ExecArgConst)
		w.write(arg.Size())
		w.write(arg.Value(pid))
		w.write(arg.Type.BitfieldOffset())
		w.write(arg.Type.BitfieldLength())
	case ArgResult:
		w.write(ExecArgResult)
		w.write(arg.Size())
		w.write(w.args[arg.Res].Idx)
		w.write(arg.OpDiv)
		w.write(arg.OpAdd)
	case ArgPointer:
		w.write(ExecArgConst)
		w.write(arg.Size())
		w.write(physicalAddr(arg))
		w.write(0) // bit field offset
		w.write(0) // bit field length
	case ArgPageSize:
		w.write(ExecArgConst)
		w.write(arg.Size())
		w.write(arg.AddrPage * pageSize)
		w.write(0) // bit field offset
		w.write(0) // bit field length
	case ArgData:
		w.write(ExecArgData)
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
	default:
		panic("unknown arg type")
	}
}
