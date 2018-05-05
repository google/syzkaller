// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file does serialization of programs for executor binary.
// The format aims at simple parsing: binary and irreversible.

// Exec format is an sequence of uint64's which encodes a sequence of calls.
// The sequence is terminated by a speciall call execInstrEOF.
// Each call is (call ID, copyout index, number of arguments, arguments...).
// Each argument is (type, size, value).
// There are 4 types of arguments:
//  - execArgConst: value is const value
//  - execArgResult: value is copyout index we want to reference
//  - execArgData: value is a binary blob (represented as ]size/8[ uint64's)
//  - execArgCsum: runtime checksum calculation
// There are 2 other special calls:
//  - execInstrCopyin: copies its second argument into address specified by first argument
//  - execInstrCopyout: reads value at address specified by first argument (result can be referenced by execArgResult)

package prog

import (
	"fmt"
	"sort"
)

const (
	execInstrEOF = ^uint64(iota)
	execInstrCopyin
	execInstrCopyout
)

const (
	execArgConst = uint64(iota)
	execArgResult
	execArgData
	execArgCsum
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
	ExecNoCopyout  = ^uint64(0)
)

// SerializeForExec serializes program p for execution by process pid into the provided buffer.
// Returns number of bytes written to the buffer.
// If the provided buffer is too small for the program an error is returned.
func (p *Prog) SerializeForExec(buffer []byte) (int, error) {
	if debug {
		if err := p.validate(); err != nil {
			panic(fmt.Errorf("serializing invalid program: %v", err))
		}
	}
	var copyoutSeq uint64
	w := &execContext{
		target: p.Target,
		buf:    buffer,
		eof:    false,
		args:   make(map[Arg]argInfo),
	}
	for _, c := range p.Calls {
		// Calculate checksums.
		csumMap := calcChecksumsCall(c)
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
		ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
			if ctx.Base == nil {
				return
			}
			addr := p.Target.PhysicalAddr(ctx.Base) + ctx.Offset
			if res, ok := arg.(*ResultArg); ok && len(res.uses) != 0 || csumUses[arg] {
				w.args[arg] = argInfo{Addr: addr}
			}
			if _, ok := arg.(*GroupArg); ok {
				return
			}
			if _, ok := arg.(*UnionArg); ok {
				return
			}
			typ := arg.Type()
			if typ.Dir() == DirOut || IsPad(typ) || arg.Size() == 0 {
				return
			}
			w.write(execInstrCopyin)
			w.write(addr)
			w.writeArg(arg)
		})
		// Generate checksum calculation instructions starting from the last one,
		// since checksum values can depend on values of the latter ones
		if csumMap != nil {
			var csumArgs []Arg
			for arg := range csumMap {
				csumArgs = append(csumArgs, arg)
			}
			sort.Slice(csumArgs, func(i, j int) bool {
				return w.args[csumArgs[i]].Addr < w.args[csumArgs[j]].Addr
			})
			for i := len(csumArgs) - 1; i >= 0; i-- {
				arg := csumArgs[i]
				if _, ok := arg.Type().(*CsumType); !ok {
					panic("csum arg is not csum type")
				}
				w.write(execInstrCopyin)
				w.write(w.args[arg].Addr)
				w.write(execArgCsum)
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
			}
		}
		// Generate the call itself.
		w.write(uint64(c.Meta.ID))
		if c.Ret != nil && len(c.Ret.uses) != 0 {
			if _, ok := w.args[c.Ret]; ok {
				panic("argInfo is already created for return value")
			}
			w.args[c.Ret] = argInfo{Idx: copyoutSeq, Ret: true}
			w.write(copyoutSeq)
			copyoutSeq++
		} else {
			w.write(ExecNoCopyout)
		}
		w.write(uint64(len(c.Args)))
		for _, arg := range c.Args {
			w.writeArg(arg)
		}
		// Generate copyout instructions that persist interesting return values.
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			if res, ok := arg.(*ResultArg); ok && len(res.uses) != 0 {
				// Create a separate copyout instruction that has own Idx.
				info := w.args[arg]
				if info.Ret {
					return // Idx is already assigned above.
				}
				info.Idx = copyoutSeq
				copyoutSeq++
				w.args[arg] = info
				w.write(execInstrCopyout)
				w.write(info.Idx)
				w.write(info.Addr)
				w.write(arg.Size())
			}
		})
	}
	w.write(execInstrEOF)
	if w.eof {
		return 0, fmt.Errorf("provided buffer is too small")
	}
	return len(buffer) - len(w.buf), nil
}

func (target *Target) PhysicalAddr(arg *PointerArg) uint64 {
	if arg.IsNull() {
		return 0
	}
	return target.DataOffset + arg.Address
}

type execContext struct {
	target *Target
	buf    []byte
	eof    bool
	args   map[Arg]argInfo
}

type argInfo struct {
	Addr uint64 // physical addr
	Idx  uint64 // copyout instruction index
	Ret  bool
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

func (w *execContext) writeArg(arg Arg) {
	switch a := arg.(type) {
	case *ConstArg:
		val, pidStride, bigEndian := a.Value()
		w.writeConstArg(a.Size(), val, a.Type().BitfieldOffset(), a.Type().BitfieldLength(),
			pidStride, bigEndian)
	case *ResultArg:
		if a.Res == nil {
			w.writeConstArg(a.Size(), a.Val, 0, 0, 0, false)
		} else {
			info, ok := w.args[a.Res]
			if !ok {
				panic("no copyout index")
			}
			w.write(execArgResult)
			w.write(a.Size())
			w.write(info.Idx)
			w.write(a.OpDiv)
			w.write(a.OpAdd)
			w.write(a.Type().(*ResourceType).Default())
		}
	case *PointerArg:
		w.writeConstArg(a.Size(), w.target.PhysicalAddr(a), 0, 0, 0, false)
	case *DataArg:
		data := a.Data()
		w.write(execArgData)
		w.write(uint64(len(data)))
		padded := len(data)
		if pad := 8 - len(data)%8; pad != 8 {
			padded += pad
		}
		if len(w.buf) < padded {
			w.eof = true
		} else {
			copy(w.buf, data)
			w.buf = w.buf[padded:]
		}
	case *UnionArg:
		w.writeArg(a.Option)
	default:
		panic("unknown arg type")
	}
}

func (w *execContext) writeConstArg(size, val, bfOffset, bfLength, pidStride uint64, bigEndian bool) {
	w.write(execArgConst)
	meta := size | bfOffset<<16 | bfLength<<24 | pidStride<<32
	if bigEndian {
		meta |= 1 << 8
	}
	w.write(meta)
	w.write(val)
}
