// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file does serialization of programs for executor binary.
// The format aims at simple parsing: binary and irreversible.

package prog

import (
	"fmt"
	"sort"

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
	ExecArgCsum
)

const (
	ExecArgCsumInet = uintptr(iota)
)

const (
	ExecArgCsumChunkData = uintptr(iota)
	ExecArgCsumChunkConst
)

const (
	ExecBufferSize = 2 << 20

	ptrSize    = 8
	pageSize   = 4 << 10
	dataOffset = 512 << 20
)

type Args []*Arg

func (s Args) Len() int {
	return len(s)
}

func (s Args) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type ByPhysicalAddr struct {
	Args
	Context *execContext
}

func (s ByPhysicalAddr) Less(i, j int) bool {
	return s.Context.args[s.Args[i]].Addr < s.Context.args[s.Args[j]].Addr
}

// SerializeForExec serializes program p for execution by process pid into the provided buffer.
// If the provided buffer is too small for the program an error is returned.
func (p *Prog) SerializeForExec(buffer []byte, pid int) error {
	if debug {
		if err := p.validate(); err != nil {
			panic(fmt.Errorf("serializing invalid program: %v", err))
		}
	}
	var instrSeq uintptr
	w := &execContext{
		buf:  buffer,
		eof:  false,
		args: make(map[*Arg]argInfo),
	}
	for _, c := range p.Calls {
		// Calculate checksums.
		csumMap := calcChecksumsCall(c, pid)
		var csumUses map[*Arg]bool
		if csumMap != nil {
			csumUses = make(map[*Arg]bool)
			for arg, info := range csumMap {
				csumUses[arg] = true
				if info.Kind == CsumInet {
					for _, chunk := range info.Chunks {
						if chunk.Kind == CsumChunkArg {
							csumUses[chunk.Arg] = true
						}
					}
				}
			}
		}
		// Calculate arg offsets within structs.
		// Generate copyin instructions that fill in data into pointer arguments.
		foreachArg(c, func(arg, _ *Arg, _ *[]*Arg) {
			if arg.Kind == ArgPointer && arg.Res != nil {
				foreachSubargOffset(arg.Res, func(arg1 *Arg, offset uintptr) {
					if len(arg1.Uses) != 0 || csumUses[arg1] {
						w.args[arg1] = argInfo{Addr: physicalAddr(arg) + offset}
					}
					if arg1.Kind == ArgGroup || arg1.Kind == ArgUnion {
						return
					}
					if !sys.IsPad(arg1.Type) &&
						!(arg1.Kind == ArgData && len(arg1.Data) == 0) &&
						arg1.Type.Dir() != sys.DirOut {
						w.write(ExecInstrCopyin)
						w.write(physicalAddr(arg) + offset)
						w.writeArg(arg1, pid, csumMap)
						instrSeq++
					}
				})
			}
		})
		// Generate checksum calculation instructions starting from the last one,
		// since checksum values can depend on values of the latter ones
		if csumMap != nil {
			var csumArgs []*Arg
			for arg, _ := range csumMap {
				csumArgs = append(csumArgs, arg)
			}
			sort.Sort(ByPhysicalAddr{Args: csumArgs, Context: w})
			for i := len(csumArgs) - 1; i >= 0; i-- {
				arg := csumArgs[i]
				if _, ok := arg.Type.(*sys.CsumType); !ok {
					panic("csum arg is not csum type")
				}
				w.write(ExecInstrCopyin)
				w.write(w.args[arg].Addr)
				w.write(ExecArgCsum)
				w.write(arg.Size())
				switch csumMap[arg].Kind {
				case CsumInet:
					w.write(ExecArgCsumInet)
					w.write(uintptr(len(csumMap[arg].Chunks)))
					for _, chunk := range csumMap[arg].Chunks {
						switch chunk.Kind {
						case CsumChunkArg:
							w.write(ExecArgCsumChunkData)
							w.write(w.args[chunk.Arg].Addr)
							w.write(chunk.Arg.Size())
						case CsumChunkConst:
							w.write(ExecArgCsumChunkConst)
							w.write(chunk.Value)
							w.write(chunk.Size)
						default:
							panic(fmt.Sprintf("csum chunk has unknown kind %v", chunk.Kind))
						}
					}
				default:
					panic(fmt.Sprintf("csum arg has unknown kind %v", csumMap[arg].Kind))
				}
				instrSeq++
			}
		}
		// Generate the call itself.
		w.write(uintptr(c.Meta.ID))
		w.write(uintptr(len(c.Args)))
		for _, arg := range c.Args {
			w.writeArg(arg, pid, csumMap)
		}
		if len(c.Ret.Uses) != 0 {
			w.args[c.Ret] = argInfo{Idx: instrSeq}
		}
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
				w.args[arg] = info
				w.write(ExecInstrCopyout)
				w.write(info.Addr)
				w.write(arg.Size())
			default:
				panic("bad arg kind in copyout")
			}
		})
	}
	w.write(ExecInstrEOF)
	if w.eof {
		return fmt.Errorf("provided buffer is too small")
	}
	return nil
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
	eof  bool
	args map[*Arg]argInfo
}

type argInfo struct {
	Addr uintptr // physical addr
	Idx  uintptr // instruction index
}

func (w *execContext) write(v uintptr) {
	if len(w.buf) < 8 {
		w.eof = true
		return
	}
	w.buf[0] = byte(v >> 0)
	w.buf[1] = byte(v >> 8)
	w.buf[2] = byte(v >> 16)
	w.buf[3] = byte(v >> 24)
	w.buf[4] = byte(v >> 32)
	w.buf[5] = byte(v >> 40)
	w.buf[6] = byte(v >> 48)
	w.buf[7] = byte(v >> 56)
	w.buf = w.buf[8:]
}

func (w *execContext) writeArg(arg *Arg, pid int, csumMap map[*Arg]CsumInfo) {
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
		padded := len(arg.Data)
		if pad := 8 - len(arg.Data)%8; pad != 8 {
			padded += pad
		}
		if len(w.buf) < padded {
			w.eof = true
		} else {
			copy(w.buf, arg.Data)
			w.buf = w.buf[padded:]
		}
	default:
		panic("unknown arg type")
	}
}
