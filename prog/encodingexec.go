// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file does serialization of programs for executor binary.
// The format aims at simple parsing: binary and irreversible.

package prog

import (
	"fmt"
	"sort"
)

const (
	ExecInstrEOF = ^uint64(iota)
	ExecInstrCopyin
	ExecInstrCopyout
)

const (
	ExecArgConst = uint64(iota)
	ExecArgResult
	ExecArgData
	ExecArgCsum
)

const (
	ExecArgCsumInet = uint64(iota)
)

const (
	ExecArgCsumChunkData = uint64(iota)
	ExecArgCsumChunkConst
)

const (
	ExecBufferSize = 2 << 20
)

type Args []Arg

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
// Returns number of bytes written to the buffer.
// If the provided buffer is too small for the program an error is returned.
func (p *Prog) SerializeForExec(buffer []byte, pid int) (int, error) {
	if debug {
		if err := p.validate(); err != nil {
			panic(fmt.Errorf("serializing invalid program: %v", err))
		}
	}
	instrSeq := 0
	w := &execContext{
		target: p.Target,
		buf:    buffer,
		eof:    false,
		args:   make(map[Arg]argInfo),
	}
	for _, c := range p.Calls {
		// Calculate checksums.
		csumMap := calcChecksumsCall(c, pid)
		var csumUses map[Arg]bool
		if csumMap != nil {
			csumUses = make(map[Arg]bool)
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
		foreachArg(c, func(arg, _ Arg, _ *[]Arg) {
			if a, ok := arg.(*PointerArg); ok && a.Res != nil {
				foreachSubargOffset(a.Res, func(arg1 Arg, offset uint64) {
					used, ok := arg1.(ArgUsed)
					if (ok && len(*used.Used()) != 0) || csumUses[arg1] {
						w.args[arg1] = argInfo{Addr: p.Target.physicalAddr(arg) + offset}
					}
					if _, ok := arg1.(*GroupArg); ok {
						return
					}
					if _, ok := arg1.(*UnionArg); ok {
						return
					}
					if a1, ok := arg1.(*DataArg); ok && len(a1.Data) == 0 {
						return
					}
					if !IsPad(arg1.Type()) && arg1.Type().Dir() != DirOut {
						w.write(ExecInstrCopyin)
						w.write(p.Target.physicalAddr(arg) + offset)
						w.writeArg(arg1, pid, csumMap)
						instrSeq++
					}
				})
			}
		})
		// Generate checksum calculation instructions starting from the last one,
		// since checksum values can depend on values of the latter ones
		if csumMap != nil {
			var csumArgs []Arg
			for arg := range csumMap {
				csumArgs = append(csumArgs, arg)
			}
			sort.Sort(ByPhysicalAddr{Args: csumArgs, Context: w})
			for i := len(csumArgs) - 1; i >= 0; i-- {
				arg := csumArgs[i]
				if _, ok := arg.Type().(*CsumType); !ok {
					panic("csum arg is not csum type")
				}
				w.write(ExecInstrCopyin)
				w.write(w.args[arg].Addr)
				w.write(ExecArgCsum)
				w.write(arg.Size())
				switch csumMap[arg].Kind {
				case CsumInet:
					w.write(ExecArgCsumInet)
					w.write(uint64(len(csumMap[arg].Chunks)))
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
		w.write(uint64(c.Meta.ID))
		w.write(uint64(len(c.Args)))
		for _, arg := range c.Args {
			w.writeArg(arg, pid, csumMap)
		}
		if len(*c.Ret.(ArgUsed).Used()) != 0 {
			w.args[c.Ret] = argInfo{Idx: instrSeq}
		}
		instrSeq++
		// Generate copyout instructions that persist interesting return values.
		foreachArg(c, func(arg, base Arg, _ *[]Arg) {
			if used, ok := arg.(ArgUsed); !ok || len(*used.Used()) == 0 {
				return
			}
			switch arg.(type) {
			case *ReturnArg:
				// Idx is already assigned above.
			case *ConstArg, *ResultArg:
				// Create a separate copyout instruction that has own Idx.
				if _, ok := base.(*PointerArg); !ok {
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
		return 0, fmt.Errorf("provided buffer is too small")
	}
	return len(buffer) - len(w.buf), nil
}

func (target *Target) physicalAddr(arg Arg) uint64 {
	a, ok := arg.(*PointerArg)
	if !ok {
		panic("physicalAddr: bad arg kind")
	}
	addr := a.PageIndex*target.PageSize + target.DataOffset
	if a.PageOffset >= 0 {
		addr += uint64(a.PageOffset)
	} else {
		addr += target.PageSize - uint64(-a.PageOffset)
	}
	return addr
}

type execContext struct {
	target *Target
	buf    []byte
	eof    bool
	args   map[Arg]argInfo
}

type argInfo struct {
	Addr uint64 // physical addr
	Idx  int    // instruction index
}

func (w *execContext) write(v uint64) {
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

func (w *execContext) writeArg(arg Arg, pid int, csumMap map[Arg]CsumInfo) {
	switch a := arg.(type) {
	case *ConstArg:
		w.write(ExecArgConst)
		w.write(a.Size())
		w.write(a.Value(pid))
		w.write(a.Type().BitfieldOffset())
		w.write(a.Type().BitfieldLength())
	case *ResultArg:
		if a.Res == nil {
			w.write(ExecArgConst)
			w.write(a.Size())
			w.write(a.Val)
			w.write(0) // bit field offset
			w.write(0) // bit field length
		} else {
			w.write(ExecArgResult)
			w.write(a.Size())
			w.write(uint64(w.args[a.Res].Idx))
			w.write(a.OpDiv)
			w.write(a.OpAdd)
		}
	case *PointerArg:
		w.write(ExecArgConst)
		w.write(a.Size())
		w.write(w.target.physicalAddr(arg))
		w.write(0) // bit field offset
		w.write(0) // bit field length
	case *DataArg:
		w.write(ExecArgData)
		w.write(uint64(len(a.Data)))
		padded := len(a.Data)
		if pad := 8 - len(a.Data)%8; pad != 8 {
			padded += pad
		}
		if len(w.buf) < padded {
			w.eof = true
		} else {
			copy(w.buf, a.Data)
			w.buf = w.buf[padded:]
		}
	default:
		panic("unknown arg type")
	}
}
