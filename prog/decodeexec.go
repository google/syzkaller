// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
)

type ExecProg struct {
	Calls []ExecCall
	Vars  []uint64
}

type ExecCall struct {
	Meta    *Syscall
	Props   CallProps
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

func ExecCallCount(exec []byte) (int, error) {
	v, n := binary.Varint(exec)
	if n <= 0 {
		return 0, fmt.Errorf("not enough data in the buffer")
	}
	if v > MaxCalls {
		return 0, fmt.Errorf("too many calls (%v)", v)
	}
	return int(v), nil
}

func (target *Target) DeserializeExec(exec []byte, stats map[string]int) (ExecProg, error) {
	dec := &execDecoder{target: target, data: exec, stats: stats}
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
	stats   map[string]int
}

func (dec *execDecoder) parse() {
	ncalls := dec.read("header")
	for dec.err == nil {
		switch instr := dec.read("instr/opcode"); instr {
		case execInstrCopyin:
			dec.commitCall()
			dec.call.Copyin = append(dec.call.Copyin, ExecCopyin{
				Addr: dec.read("instr/copyin") + dec.target.DataOffset,
				Arg:  dec.readArg(),
			})
		case execInstrCopyout:
			dec.call.Copyout = append(dec.call.Copyout, ExecCopyout{
				Index: dec.read("instr/copyout/index"),
				Addr:  dec.read("instr/copyout/addr") + dec.target.DataOffset,
				Size:  dec.read("instr/copyout/size"),
			})
		case execInstrEOF:
			dec.commitCall()
			if ncalls != uint64(len(dec.calls)) {
				dec.err = fmt.Errorf("bad number of calls: %v/%v", ncalls, len(dec.calls))
			}
			return
		case execInstrSetProps:
			dec.commitCall()
			dec.readCallProps(&dec.call.Props)
		default:
			dec.commitCall()
			if instr >= uint64(len(dec.target.Syscalls)) {
				dec.setErr(fmt.Errorf("bad syscall %v", instr))
				return
			}
			dec.call.Meta = dec.target.Syscalls[instr]
			dec.call.Index = dec.read("instr/index")
			for i := dec.read("instr/nargs"); i > 0; i-- {
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

func (dec *execDecoder) readCallProps(props *CallProps) {
	props.ForeachProp(func(_, _ string, value reflect.Value) {
		arg := dec.read("call prop")
		switch kind := value.Kind(); kind {
		case reflect.Int:
			value.SetInt(int64(arg))
		case reflect.Bool:
			if arg == 1 {
				value.SetBool(true)
			}
		default:
			panic("Unsupported (yet) kind: " + kind.String())
		}
	})
}

func (dec *execDecoder) readArg() ExecArg {
	switch typ := dec.read("arg/type"); typ {
	case execArgConst:
		meta := dec.read("arg/const/meta")
		return ExecArgConst{
			Value:          dec.read("arg/const/value"),
			Size:           meta & 0xff,
			Format:         BinaryFormat((meta >> 8) & 0xff),
			BitfieldOffset: (meta >> 16) & 0xff,
			BitfieldLength: (meta >> 24) & 0xff,
			PidStride:      meta >> 32,
		}
	case execArgAddr32:
		fallthrough
	case execArgAddr64:
		size := 4
		if typ == execArgAddr64 {
			size = 8
		}
		return ExecArgConst{
			Value: dec.read("arg/addr") + dec.target.DataOffset,
			Size:  uint64(size),
		}
	case execArgResult:
		meta := dec.read("arg/result/meta")
		arg := ExecArgResult{
			Size:    meta & 0xff,
			Format:  BinaryFormat((meta >> 8) & 0xff),
			Index:   dec.read("arg/result/index"),
			DivOp:   dec.read("arg/result/divop"),
			AddOp:   dec.read("arg/result/addop"),
			Default: dec.read("arg/result/default"),
		}
		for uint64(len(dec.vars)) <= arg.Index {
			dec.vars = append(dec.vars, 0)
		}
		dec.vars[arg.Index] = arg.Default
		return arg
	case execArgData:
		flags := dec.read("arg/data/size")
		size := flags & ^execArgDataReadable
		dec.addStat("arg/data/blob", int(size))
		readable := flags&execArgDataReadable != 0
		return ExecArgData{
			Data:     dec.readBlob(size),
			Readable: readable,
		}
	case execArgCsum:
		size := dec.read("arg/csum/size")
		switch kind := dec.read("arg/csum/kind"); kind {
		case ExecArgCsumInet:
			chunks := make([]ExecCsumChunk, dec.read("arg/csum/chunks"))
			for i := range chunks {
				kind := dec.read("arg/csum/chunk/kind")
				addr := dec.read("arg/csum/chunk/addr")
				size := dec.read("arg/csum/chunk/size")
				if kind == ExecArgCsumChunkData {
					addr += dec.target.DataOffset
				}
				chunks[i] = ExecCsumChunk{
					Kind:  kind,
					Value: addr,
					Size:  size,
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

func (dec *execDecoder) read(stat string) uint64 {
	if dec.err != nil {
		return 0
	}
	v, n := binary.Varint(dec.data)
	if n <= 0 {
		dec.setErr(fmt.Errorf("exec program overflow"))
		return 0
	}
	dec.addStat(stat, n)
	dec.data = dec.data[n:]
	return uint64(v)
}

func (dec *execDecoder) readBlob(size uint64) []byte {
	if uint64(len(dec.data)) < size {
		dec.setErr(fmt.Errorf("exec program overflow"))
	}
	if dec.err != nil {
		return nil
	}
	data := dec.data[:size]
	dec.data = dec.data[size:]
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
		dec.numVars = max(dec.numVars, copyout.Index+1)
	}
	dec.calls = append(dec.calls, dec.call)
	dec.call = ExecCall{}
}

func (dec *execDecoder) addStat(stat string, n int) {
	if dec.stats == nil {
		return
	}
	prefix := ""
	for _, part := range strings.Split(stat, "/") {
		dec.stats[prefix+part] += n
		prefix += part + "/"
	}
}
