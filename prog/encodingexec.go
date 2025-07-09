// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file does serialization of programs for executor binary.
// The format aims at simple parsing: binary and irreversible.

// Exec format is an sequence of uint64's which encodes a sequence of calls.
// The sequence is terminated by a speciall call execInstrEOF.
// Each call is (call ID, copyout index, number of arguments, arguments...).
// Each argument is (type, size, value).
// There are the following types of arguments:
//  - execArgConst: value is const value
//  - execArgAddr32/64: constant address
//  - execArgResult: value is copyout index we want to reference
//  - execArgData: value is a binary blob (represented as ]size/8[ uint64's)
//  - execArgCsum: runtime checksum calculation
// There are the following special calls:
//  - execInstrCopyin: copies its second argument into address specified by first argument
//  - execInstrCopyout: reads value at address specified by first argument (result can be referenced by execArgResult)
//  - execInstrSetProps: sets special properties for the previous call

package prog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"sort"
)

const (
	execInstrEOF = ^uint64(iota)
	execInstrCopyin
	execInstrCopyout
	execInstrSetProps
)

const (
	execArgConst = uint64(iota)
	execArgAddr32
	execArgAddr64
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

	execMaxCommands = 1000 // executor knows about this constant (kMaxCommands)
)

// XXX: It is easy to determine this dynamically in the manager, it's just a
// question of finding a good place to do this.
const syz_kfuzztest_run_id int = 7367

// SerializeForExec serializes program p for execution by process pid into the provided buffer.
// Returns number of bytes written to the buffer.
// If the provided buffer is too small for the program an error is returned.
func (p *Prog) SerializeForExec() ([]byte, error) {
	// Rewrite all calls for pseudo-syscall syz_kfuzztest_run so that they have
	// the ID that the executor is expecting, as since these are discovered
	// dynamically the executor is not aware of their existence.
	// for _, call := range p.Calls {
	// 	if call.Meta.CallName == "syz_kfuzztest_run" {
	// 		call.Meta.ID = syz_kfuzztest_run_id
	// 	}
	// }

	p.debugValidate()
	w := &execContext{
		target: p.Target,
		buf:    make([]byte, 0, 4<<10),
		args:   make(map[Arg]argInfo),
	}
	w.write(uint64(len(p.Calls)))
	for _, c := range p.Calls {
		w.csumMap, w.csumUses = calcChecksumsCall(c)
		w.serializeCall(c)
	}
	w.write(execInstrEOF)
	if len(w.buf) > ExecBufferSize {
		return nil, fmt.Errorf("encodingexec: too large program (%v/%v)", len(w.buf), ExecBufferSize)
	}
	if w.copyoutSeq > execMaxCommands {
		return nil, fmt.Errorf("encodingexec: too many resources (%v/%v)", w.copyoutSeq, execMaxCommands)
	}
	return w.buf, nil
}

func (w *execContext) serializeCall(c *Call) {
	// we introduce special serialization logic for kfuzztest targets, which
	// require special handling due to their use of relocation tables to copy
	// entire blobs of data into the kenrel.
	if c.Meta.CallName == "syz_kfuzztest_run" {
		w.serializeKFuzzTestCall(c)
		return
	}

	// Calculate arg offsets within structs.
	// Generate copyin instructions that fill in data into pointer arguments.
	w.writeCopyin(c)
	// Generate checksum calculation instructions starting from the last one,
	// since checksum values can depend on values of the latter ones
	w.writeChecksums()
	if !reflect.DeepEqual(c.Props, CallProps{}) {
		// Push call properties.
		w.writeCallProps(c.Props)
	}
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

// KFuzzTest targets require special handling due to their use of relocation
// tables for serializing all data (including pointed-to data) into a
// continuous blob that can be passed into the kernel.
func (w *execContext) serializeKFuzzTestCall(c *Call) {
	if c.Meta.CallName != "syz_kfuzztest_run" {
		// This is a specialized function that shouldn't be called on anything
		// other than an instance of a syz_kfuzztest_run$* syscall
		panic("serializeKFuzzTestCall called on an invalid syscall")
	}

	// Write the initial string argument (test name) normally
	w.writeCopyin(&Call{Meta: c.Meta, Args: []Arg{c.Args[0]}})

	// Args[1] is the second argument to syz_kfuzztest_run, which is a pointer
	// to some struct input. This is the data that must be flattened and sent
	// to the fuzzing driver with a relocation table.
	dataArg := c.Args[1].(*PointerArg)
	finalBlob := marshallKFuzztestArg(dataArg.Res)

	// Reuse the memory address that was pre-allocated for the original struct
	// argument. This avoids needing to hook into the memory allocation which
	// is done at a higher level than the serialization. This relies on the
	// original buffer being large enough
	blobAddress := w.target.PhysicalAddr(dataArg) - w.target.DataOffset

	// Write the entire marshalled blob as a raw byte array.
	w.write(execInstrCopyin)
	w.write(blobAddress)
	w.write(execArgData)
	w.write(uint64(len(finalBlob)))
	w.buf = append(w.buf, finalBlob...)

	// Update the value of the length arg which should now match the length of
	// the byte array that we created. Previously, it contained the bytesize
	// of the struct argument passed into the pseudo-syscall
	lenArg := c.Args[2].(*ConstArg)
	lenArg.Val = uint64(len(finalBlob))

	// Generate the final syscall instruction with the update arguments.
	w.write(uint64(c.Meta.ID))
	w.write(ExecNoCopyout)
	w.write(uint64(len(c.Args)))
	for _, arg := range c.Args {
		w.writeArg(arg)
	}
}

type execContext struct {
	target     *Target
	buf        []byte
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

func (w *execContext) writeCallProps(props CallProps) {
	w.write(execInstrSetProps)
	props.ForeachProp(func(_, _ string, value reflect.Value) {
		var uintVal uint64
		switch kind := value.Kind(); kind {
		case reflect.Int:
			uintVal = uint64(value.Int())
		case reflect.Bool:
			if value.Bool() {
				uintVal = 1
			}
		default:
			panic("Unsupported (yet) kind: " + kind.String())
		}
		w.write(uintVal)
	})
}

func (w *execContext) writeCopyin(c *Call) {
	ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
		if ctx.Base == nil {
			return
		}
		addr := w.target.PhysicalAddr(ctx.Base) - w.target.DataOffset + ctx.Offset
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

// marshallKFuzztestArg serializes a top-level struct argument (`topLevel`) into
// a single binary blob that can be consumed by the kernel. The output format,
// defined in `linux/include/kftf.h`, is designed for position-independent data
// transfer and consists of a relocation table followed by a raw data payload.
//
// The function serializes the tree-like Arg structure using a level-order
// traversal. This approach ensures that nested structures are
// ensuring that nested structures are laid out contiguously in memory. If
// pointer arguments are found, the pointed-to data will be laid out directly
// after the structure that the pointer is found in.
//
// The process works as follows:
//  1. All non-pointer fields of the input struct are processed first from a
//     queue, and their raw data is written sequentially into the main `payload`
//     buffer.
//  2. When a pointer is encountered, a placeholder is written into the payload,
//     and a `relocationEntry` is created and deferred to a separate pointer
//     queue. The `entry.pointer` field is set to the current offset within the
//     payload.
//  3. After all primary struct data is serialized, the pointer queue is
//     processed. The data pointed to by each deferred entry is serialized at
//     the end of the payload, and the `entry.value` is calculated as the
//     relative offset between the pointer's location and its target data.
//  4. Finally, the completed `relocation_table` is serialized and prepended to
//     the `payload` buffer to form the complete binary blob.
func marshallKFuzztestArg(topLevel Arg) []byte {
	type deferredPtr struct {
		pointedToArg Arg
		pointer      uint64
	}
	// see `linux/include/kftf.h`
	type relocationEntry struct {
		pointer uint64
		value   uint64
	}
	// Two-levels of queuing - those that must be handled directly (constants,
	// nested structures) and those that must be handled afterwards. This
	// implements a level-order traversal starting at `topLevel` such that we
	// only expand pointed-to data after all constants in the current structure
	// have already been laid out in the payload.
	layoutQueue := []Arg{topLevel}
	deferredPointers := make([]deferredPtr, 0)

	relocationTableEntries := make([]relocationEntry, 0)
	var payload bytes.Buffer
	for {
		if len(layoutQueue) == 0 && len(deferredPointers) == 0 {
			break
		}
		// Pop from layoutQueue if anything is available, else pop from the
		// deferredPointers which contains pointed-to data that we must handle
		var arg Arg
		if len(layoutQueue) > 0 {
			arg = layoutQueue[0]
			layoutQueue = layoutQueue[1:]
		} else if len(deferredPointers) > 0 {
			// pop from deferredPointers and create a relocation table entry
			dp := deferredPointers[0]
			deferredPointers = deferredPointers[1:]

			currOffset := uint64(payload.Len())
			value := currOffset - dp.pointer
			relocationTableEntries = append(relocationTableEntries,
				relocationEntry{pointer: dp.pointer, value: value})
			arg = dp.pointedToArg
		} else {
			panic("at least one queue should have remaining entries at this point")
		}

		switch a := arg.(type) {
		case *PointerArg:
			ptrOffset := payload.Len()
			// We write a placeholder value. It doesn't matter what is written
			// here because the kernel will patch these pointers based only on
			// the relocation table.
			binary.Write(&payload, binary.LittleEndian, uint64(0xBFACE))
			// NOTE: No support for VMA yet, but shouldn't be too hard to
			// handle
			if a.Res != nil {
				deferred := deferredPtr{
					pointedToArg: a.Res,
					pointer:      uint64(ptrOffset),
				}
				deferredPointers = append(deferredPointers, deferred)
			}
		// handle non-pointer arguments by writing them into the payload buffer
		case *GroupArg:
			for _, inner := range a.Inner {
				layoutQueue = append(layoutQueue, inner)
			}
		case *DataArg:
			data := a.Data()
			payload.Write(data)
		case *ConstArg:
			val, _ := a.Value()
			binary.Write(&payload, binary.LittleEndian, val)
		default:
			panic(fmt.Sprintf("tried to serialize unsupported type: %s", a.Type().Name()))
		}
	}

	var relocationTable bytes.Buffer
	numEntries := int32(len(relocationTableEntries))
	binary.Write(&relocationTable, binary.LittleEndian, numEntries)
	// 12 bytes of padding in the C-struct definition
	binary.Write(&relocationTable, binary.LittleEndian, make([]byte, 12))

	// loop over relocation entries
	for _, entry := range relocationTableEntries {
		binary.Write(&relocationTable, binary.LittleEndian, uint64(entry.pointer))
		binary.Write(&relocationTable, binary.LittleEndian, uint64(entry.value))
	}

	out := append(relocationTable.Bytes(), payload.Bytes()...)
	fmt.Printf("kftf: output len = %d\n", len(out))
	return out
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
	w.buf = binary.AppendVarint(w.buf, int64(v))
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
		switch a.Size() {
		case 4:
			w.write(execArgAddr32)
		case 8:
			w.write(execArgAddr64)
		default:
			panic(fmt.Sprintf("bad pointer address size %v", a.Size()))
		}
		w.write(w.target.PhysicalAddr(a) - w.target.DataOffset)
	case *DataArg:
		data := a.Data()
		if len(data) == 0 {
			panic("writing data arg with 0 size")
		}
		w.write(execArgData)
		flags := uint64(len(data))
		if isReadableDataType(a.Type().(*BufferType)) {
			flags |= execArgDataReadable
		}
		w.write(flags)
		w.buf = append(w.buf, data...)
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
