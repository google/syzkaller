// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

type ExecProg struct {
	Calls []ExecCall
	Vars  []uint64
}

type ExecCall struct {
	Meta    *Syscall
	Index   uint64
	Args    []ExecArg
	Copyin  []ExecCopyin
	Copyout []ExecCopyout
}

type ExecCopyin struct {
	Addr uint64
	Arg  ExecArg
}

type ExecCopyout struct {
	Index uint64
	Addr  uint64
	Size  uint64
}

type ExecArg interface{} // one of ExecArg*

type ExecArgConst struct {
	Size           uint64
	Format         BinaryFormat
	Value          uint64
	BitfieldOffset uint64
	BitfieldLength uint64
	PidStride      uint64
}

type ExecArgResult struct {
	Size    uint64
	Format  BinaryFormat
	Index   uint64
	DivOp   uint64
	AddOp   uint64
	Default uint64
}

type ExecArgData struct {
	Data     []byte
	Readable bool
}

type ExecArgCsum struct {
	Size   uint64
	Kind   uint64
	Chunks []ExecCsumChunk
}

type ExecCsumChunk struct {
	Kind  uint64
	Value uint64
	Size  uint64
}

func (target *Target) DeserializeExec(exec []byte) (ExecProg, error) {
	dec := &execDecoder{target: target, data: exec}
	dec.parse()
	if dec.err != nil {
		return ExecProg{}, dec.err
	}
	if uint64(len(dec.vars)) != dec.numVars {
		return ExecProg{}, fmt.Errorf("mismatching number of vars: %v/%v",
			len(dec.vars), dec.numVars)
	}
	p := ExecProg{
		Calls: dec.calls,
		Vars:  dec.vars,
	}
	return p, nil
}

type execDecoder struct {
	target  *Target
	data    []byte
	err     error
	numVars uint64
	vars    []uint64
	call    ExecCall
	calls   []ExecCall
}

func (dec *execDecoder) parse() {
	for dec.err == nil {
		switch instr := dec.read(); instr {
		case execInstrCopyin:
			dec.commitCall()
			dec.call.Copyin = append(dec.call.Copyin, ExecCopyin{
				Addr: dec.read(),
				Arg:  dec.readArg(),
			})
		case execInstrCopyout:
			dec.call.Copyout = append(dec.call.Copyout, ExecCopyout{
				Index: dec.read(),
				Addr:  dec.read(),
				Size:  dec.read(),
			})
		case execInstrEOF:
			dec.commitCall()
			return
		default:
			dec.commitCall()
			if instr >= uint64(len(dec.target.Syscalls)) {
				dec.setErr(fmt.Errorf("bad syscall %v", instr))
				return
			}
			dec.call.Meta = dec.target.Syscalls[instr]
			dec.call.Index = dec.read()
			for i := dec.read(); i > 0; i-- {
				switch arg := dec.readArg(); arg.(type) {
				case ExecArgConst, ExecArgResult:
					dec.call.Args = append(dec.call.Args, arg)
				default:
					dec.setErr(fmt.Errorf("bad call arg %+v", arg))
					return
				}
			}
		}
	}
}

func (dec *execDecoder) readArg() ExecArg {
	switch typ := dec.read(); typ {
	case execArgConst:
		meta := dec.read()
		return ExecArgConst{
			Value:          dec.read(),
			Size:           meta & 0xff,
			Format:         BinaryFormat((meta >> 8) & 0xff),
			BitfieldOffset: (meta >> 16) & 0xff,
			BitfieldLength: (meta >> 24) & 0xff,
			PidStride:      meta >> 32,
		}
	case execArgResult:
		meta := dec.read()
		arg := ExecArgResult{
			Size:    meta & 0xff,
			Format:  BinaryFormat((meta >> 8) & 0xff),
			Index:   dec.read(),
			DivOp:   dec.read(),
			AddOp:   dec.read(),
			Default: dec.read(),
		}
		for uint64(len(dec.vars)) <= arg.Index {
			dec.vars = append(dec.vars, 0)
		}
		dec.vars[arg.Index] = arg.Default
		return arg
	case execArgData:
		flags := dec.read()
		size := flags & ^execArgDataReadable
		readable := flags&execArgDataReadable != 0
		return ExecArgData{
			Data:     dec.readBlob(size),
			Readable: readable,
		}
	case execArgCsum:
		size := dec.read()
		switch kind := dec.read(); kind {
		case ExecArgCsumInet:
			chunks := make([]ExecCsumChunk, dec.read())
			for i := range chunks {
				chunks[i] = ExecCsumChunk{
					Kind:  dec.read(),
					Value: dec.read(),
					Size:  dec.read(),
				}
			}
			return ExecArgCsum{
				Size:   size,
				Kind:   kind,
				Chunks: chunks,
			}
		default:
			dec.setErr(fmt.Errorf("unknown csum kind %v", kind))
			return nil
		}
	default:
		dec.setErr(fmt.Errorf("bad argument type %v", typ))
		return nil
	}
}

func (dec *execDecoder) read() uint64 {
	if len(dec.data) < 8 {
		dec.setErr(fmt.Errorf("exec program overflow"))
	}
	if dec.err != nil {
		return 0
	}
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(dec.data[i]) << uint(i*8)
	}
	dec.data = dec.data[8:]
	return v
}

func (dec *execDecoder) readBlob(size uint64) []byte {
	padded := (size + 7) / 8 * 8
	if uint64(len(dec.data)) < padded {
		dec.setErr(fmt.Errorf("exec program overflow"))
	}
	if dec.err != nil {
		return nil
	}
	data := dec.data[:size]
	dec.data = dec.data[padded:]
	return data
}

func (dec *execDecoder) setErr(err error) {
	if dec.err == nil {
		dec.err = err
	}
}

func (dec *execDecoder) commitCall() {
	if dec.call.Meta == nil {
		return
	}
	if dec.call.Index != ExecNoCopyout && dec.numVars < dec.call.Index+1 {
		dec.numVars = dec.call.Index + 1
	}
	for _, copyout := range dec.call.Copyout {
		if dec.numVars < copyout.Index+1 {
			dec.numVars = copyout.Index + 1
		}
	}
	dec.calls = append(dec.calls, dec.call)
	dec.call = ExecCall{}
}
