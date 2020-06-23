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

	execArgDataReadable = uint64(1 << 63)
)

const (
	ExecArgCsumInet = uint64(iota)
)

const (
	ExecArgCsumChunkData = uint64(iota)
	ExecArgCsumChunkConst
)

const (
	ExecBufferSize = 4 << 20 // keep in sync with kMaxInput in executor.cc
	ExecNoCopyout  = ^uint64(0)
)

// SerializeForExec serializes program p for execution by process pid into the provided buffer.
// Returns number of bytes written to the buffer.
// If the provided buffer is too small for the program an error is returned.
func (p *Prog) SerializeForExec(buffer []byte) (int, error) {
	p.debugValidate()
	w := &execContext{
		target: p.Target,
		buf:    buffer,
		eof:    false,
		args:   make(map[Arg]argInfo),
	}
	for _, c := range p.Calls {
		w.csumMap, w.csumUses = calcChecksumsCall(c)
		w.serializeCall(c)
	}
	w.write(execInstrEOF)
	if w.eof {
		return 0, fmt.Errorf("provided buffer is too small")
	}
	return len(buffer) - len(w.buf), nil
}

func (w *execContext) serializeCall(c *Call) {
	// Calculate arg offsets within structs.
	// Generate copyin instructions that fill in data into pointer arguments.
	w.writeCopyin(c)
	// Generate checksum calculation instructions starting from the last one,
	// since checksum values can depend on values of the latter ones
	w.writeChecksums()
	// Generate the call itself.
	w.write(uint64(c.Meta.ID))
	if c.Ret != nil && len(c.Ret.uses) != 0 {
		if _, ok := w.args[c.Ret]; ok {
			panic("argInfo is already created for return value")
		}
		w.args[c.Ret] = argInfo{Idx: w.copyoutSeq, Ret: true}
		w.write(w.copyoutSeq)
		w.copyoutSeq++
	} else {
		w.write(ExecNoCopyout)
	}
	w.write(uint64(len(c.Args)))
	for _, arg := range c.Args {
		w.writeArg(arg)
	}
	// Generate copyout instructions that persist interesting return values.
	w.writeCopyout(c)
}

type execContext struct {
	target     *Target
	buf        []byte
	eof        bool
	args       map[Arg]argInfo
	copyoutSeq uint64
	// Per-call state cached here to not pass it through all functions.
	csumMap  map[Arg]CsumInfo
	csumUses map[Arg]struct{}
}

type argInfo struct {
	Addr uint64 // physical addr
	Idx  uint64 // copyout instruction index
	Ret  bool
}

func (w *execContext) writeCopyin(c *Call) {
	ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
		if ctx.Base == nil {
			return
		}
		addr := w.target.PhysicalAddr(ctx.Base) + ctx.Offset
		addr -= arg.Type().UnitOffset()
		if w.willBeUsed(arg) {
			w.args[arg] = argInfo{Addr: addr}
		}
		switch arg.(type) {
		case *GroupArg, *UnionArg:
			return
		}
		typ := arg.Type()
		if arg.Dir() == DirOut || IsPad(typ) || (arg.Size() == 0 && !typ.IsBitfield()) {
			return
		}
		w.write(execInstrCopyin)
		w.write(addr)
		w.writeArg(arg)
	})
}

func (w *execContext) willBeUsed(arg Arg) bool {
	if res, ok := arg.(*ResultArg); ok && len(res.uses) != 0 {
		return true
	}
	_, ok1 := w.csumMap[arg]
	_, ok2 := w.csumUses[arg]
	return ok1 || ok2
}

func (w *execContext) writeChecksums() {
	if len(w.csumMap) == 0 {
		return
	}
	csumArgs := make([]Arg, 0, len(w.csumMap))
	for arg := range w.csumMap {
		csumArgs = append(csumArgs, arg)
	}
	sort.Slice(csumArgs, func(i, j int) bool {
		return w.args[csumArgs[i]].Addr < w.args[csumArgs[j]].Addr
	})
	for i := len(csumArgs) - 1; i >= 0; i-- {
		arg := csumArgs[i]
		info := w.csumMap[arg]
		if _, ok := arg.Type().(*CsumType); !ok {
			panic("csum arg is not csum type")
		}
		w.write(execInstrCopyin)
		w.write(w.args[arg].Addr)
		w.write(execArgCsum)
		w.write(arg.Size())
		switch info.Kind {
		case CsumInet:
			w.write(ExecArgCsumInet)
			w.write(uint64(len(info.Chunks)))
			for _, chunk := range info.Chunks {
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
			panic(fmt.Sprintf("csum arg has unknown kind %v", info.Kind))
		}
	}
}

func (w *execContext) writeCopyout(c *Call) {
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		if res, ok := arg.(*ResultArg); ok && len(res.uses) != 0 {
			// Create a separate copyout instruction that has own Idx.
			info := w.args[arg]
			if info.Ret {
				return // Idx is already assigned above.
			}
			info.Idx = w.copyoutSeq
			w.copyoutSeq++
			w.args[arg] = info
			w.write(execInstrCopyout)
			w.write(info.Idx)
			w.write(info.Addr)
			w.write(arg.Size())
		}
	})
}

func (w *execContext) write(v uint64) {
	if len(w.buf) < 8 {
		w.eof = true
		return
	}
	HostEndian.PutUint64(w.buf, v)
	w.buf = w.buf[8:]
}

func (w *execContext) writeArg(arg Arg) {
	switch a := arg.(type) {
	case *ConstArg:
		val, pidStride := a.Value()
		typ := a.Type()
		w.writeConstArg(typ.UnitSize(), val, typ.BitfieldOffset(), typ.BitfieldLength(), pidStride, typ.Format())
	case *ResultArg:
		if a.Res == nil {
			w.writeConstArg(a.Size(), a.Val, 0, 0, 0, a.Type().Format())
		} else {
			info, ok := w.args[a.Res]
			if !ok {
				panic("no copyout index")
			}
			w.write(execArgResult)
			meta := a.Size() | uint64(a.Type().Format())<<8
			w.write(meta)
			w.write(info.Idx)
			w.write(a.OpDiv)
			w.write(a.OpAdd)
			w.write(a.Type().(*ResourceType).Default())
		}
	case *PointerArg:
		w.writeConstArg(a.Size(), w.target.PhysicalAddr(a), 0, 0, 0, FormatNative)
	case *DataArg:
		data := a.Data()
		if len(data) == 0 {
			return
		}
		w.write(execArgData)
		flags := uint64(len(data))
		if isReadableDataType(a.Type().(*BufferType)) {
			flags |= execArgDataReadable
		}
		w.write(flags)
		padded := len(data)
		if pad := 8 - len(data)%8; pad != 8 {
			padded += pad
		}
		if len(w.buf) < padded {
			w.eof = true
		} else {
			copy(w.buf, data)
			copy(w.buf[len(data):], make([]byte, 8))
			w.buf = w.buf[padded:]
		}
	case *UnionArg:
		w.writeArg(a.Option)
	default:
		panic("unknown arg type")
	}
}

func (w *execContext) writeConstArg(size, val, bfOffset, bfLength, pidStride uint64, bf BinaryFormat) {
	w.write(execArgConst)
	meta := size | uint64(bf)<<8 | bfOffset<<16 | bfLength<<24 | pidStride<<32
	w.write(meta)
	w.write(val)
}
