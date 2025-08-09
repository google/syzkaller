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

	// Write the initial string argument (test name) normally.
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
	// of the struct argument passed into the pseudo-syscall.
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

// Special value for making null pointers that equals (void *)-1
const kFuzzTestNilPtrVal uint32 = ^uint32(0)

const kFuzzTestPoisonSize uint64 = 0x8

func isPowerOfTwo(n uint64) bool {
	return n > 0 && (n&(n-1) == 0)
}

func roundUpPowerOfTwo(x, n uint64) uint64 {
	if !isPowerOfTwo(n) {
		panic("n was not a power of 2")
	}
	return (x + n - 1) &^ (n - 1)
}

// Pad b so that it's length is a multiple of alignment, with at least
// minPadding bytes of padding, where alignment is a power of 2.
func padWithAlignment(b *bytes.Buffer, alignment, minPadding uint64) {
	var newSize uint64
	if alignment == 0 {
		newSize = uint64(b.Len()) + minPadding
	} else {
		newSize = roundUpPowerOfTwo(uint64(b.Len())+minPadding, alignment)
	}

	paddingBytes := newSize - uint64(b.Len())
	for range paddingBytes {
		b.WriteByte(byte(0))
	}
}

type sliceQueue[T any] struct {
	q []T
}

func (sq *sliceQueue[T]) push(elem T) {
	sq.q = append(sq.q, elem)
}

func (sq *sliceQueue[T]) pop() T {
	ret := sq.q[0]
	sq.q = sq.q[1:]
	return ret
}

func (sq *sliceQueue[T]) isEmpty() bool {
	return len(sq.q) == 0
}

func newSliceQueue[T any]() *sliceQueue[T] {
	return &sliceQueue[T]{q: make([]T, 0)}
}

type kFuzzTestRelocation struct {
	offset    uint32
	srcRegion Arg
	dstRegion Arg
}

type kFuzzTestRegion struct {
	offset uint32
	size   uint32
}

// The following helpers and definitions follow directly from the C-struct
// definitions in <include/linux/kfuzztest.h>.
const kFuzzTestRegionSize = 8

func kFuzzTestRegionArraySize(numRegions int) int {
	return 4 + kFuzzTestRegionSize*numRegions
}

func kFuzzTestWriteRegion(buf *bytes.Buffer, region kFuzzTestRegion) {
	binary.Write(buf, binary.LittleEndian, region.offset)
	binary.Write(buf, binary.LittleEndian, region.size)
}

func kFuzzTestWriteRegionArray(buf *bytes.Buffer, regions []kFuzzTestRegion) {
	binary.Write(buf, binary.LittleEndian, uint32(len(regions)))
	for _, reg := range regions {
		kFuzzTestWriteRegion(buf, reg)
	}
}

const kFuzzTestRelocationSize = 12

func kFuzzTestRelocTableSize(numRelocs int) int {
	return 8 + kFuzzTestRelocationSize*numRelocs
}

func kFuzzTestWriteReloc(buf *bytes.Buffer, regToId *map[Arg]int, reloc kFuzzTestRelocation) {
	binary.Write(buf, binary.LittleEndian, uint32((*regToId)[reloc.srcRegion]))
	binary.Write(buf, binary.LittleEndian, reloc.offset)
	if reloc.dstRegion == nil {
		binary.Write(buf, binary.LittleEndian, kFuzzTestNilPtrVal)
	} else {
		binary.Write(buf, binary.LittleEndian, uint32((*regToId)[reloc.dstRegion]))
	}
}

func kFuzzTestWriteRelocTable(buf *bytes.Buffer, regToId *map[Arg]int,
	relocations []kFuzzTestRelocation, paddingBytes uint64) {
	binary.Write(buf, binary.LittleEndian, uint32(len(relocations)))
	binary.Write(buf, binary.LittleEndian, uint32(paddingBytes))
	for _, reloc := range relocations {
		kFuzzTestWriteReloc(buf, regToId, reloc)
	}
	buf.Write(make([]byte, paddingBytes))
}

// Expands a region, and returns a list of relocations that need to be made.
func kFuzzTestExpandRegion(reg Arg) ([]byte, []kFuzzTestRelocation) {
	relocations := []kFuzzTestRelocation{}
	var encoded bytes.Buffer
	queue := newSliceQueue[Arg]()
	queue.push(reg)

	for {
		if queue.isEmpty() {
			break
		}

		arg := queue.pop()
		padWithAlignment(&encoded, arg.Type().Alignment(), 0)

		switch a := arg.(type) {
		case *PointerArg:
			offset := uint32(encoded.Len())
			binary.Write(&encoded, binary.LittleEndian, uint64(0xFFFFFFFFFFFFFFFF))
			relocations = append(relocations, kFuzzTestRelocation{offset, reg, a.Res})
		case *GroupArg:
			for _, inner := range a.Inner {
				queue.push(inner)
			}
		case *DataArg:
			encoded.Write(a.data)
		case *ConstArg:
			val, _ := a.Value()
			switch a.Size() {
			case 1:
				binary.Write(&encoded, binary.LittleEndian, uint8(val))
			case 2:
				binary.Write(&encoded, binary.LittleEndian, uint16(val))
			case 4:
				binary.Write(&encoded, binary.LittleEndian, uint32(val))
			case 8:
				binary.Write(&encoded, binary.LittleEndian, uint64(val))
			default:
				panic(fmt.Sprintf("unsupported constant size: %d", a.Size()))
			}
			// TODO: handle union args.
		default:
			panic(fmt.Sprintf("tried to serialize unsupported type: %s", a.Type().Name()))
		}
	}

	return encoded.Bytes(), relocations
}

// marshallKFuzzTestArg serializes a syzkaller Arg into a flat binary format
// understood by the KFuzzTest kernel interface (see `include/linux/kfuzztest.h`).
//
// The goal is to represent a tree-like structure of arguments (which may contain
// pointers and cycles) as a single byte slice that the kernel can deserialize
// into a set of distinct heap allocations.
//
// The binary format consists of three contiguous parts, in this order:
//
//  1. Region Array: A header describing all logical memory regions that will be
//     allocated by the kernel. Each `relocRegion` defines a region's unique `id`,
//     its `size`, its `alignment`, and its `start` offset within the payload.
//     The kernel uses this table to create one distinct heap allocation per region.
//
//  2. Relocation Table: A header containing a list of `relocationEntry` structs.
//     Each entry identifies the location of a pointer field within the payload
//     (via a `regionID` and `regionOffset`) and maps it to the logical region
//     it points to (via a `value` which holds the pointee's `regionID`).
//     A NULL pointer is identified by the special value `kFuzzTestNilPtrVal`.
//
//  3. Payload: The raw, serialized data for all arguments, laid out as a single
//     contiguous block of memory.
//
// The serialization algorithm performs a multi-level, level-order traversal of the
// argument graph, starting from the `topLevel` argument. This traversal is managed
// by two queues: one for the immediate fields of a struct, and a second "deferred"
// queue for the pointees of any pointer arguments. This ensures that when a
// pointer is encountered, its pointee is only expanded after the entire
// structure containing the pointer has been serialized into the payload.
//
// Cycles are handled by tracking visited arguments, ensuring that a region for a
// given pointee is allocated only once.
//
// For a concrete example of the final binary layout, see the test cases for this
// function in `prog/encodingexec_test.go`.
func marshallKFuzztestArg(topLevel Arg) []byte {
	regions := []kFuzzTestRegion{}
	allRelocations := []kFuzzTestRelocation{}
	visitedRegions := make(map[Arg]int)
	queue := newSliceQueue[Arg]()
	var payload bytes.Buffer
	queue.push(topLevel)
	maxAlignment := uint64(8)

Loop:
	for {
		if queue.isEmpty() {
			break Loop
		}

		reg := queue.pop()
		if _, visited := visitedRegions[reg]; visited {
			continue Loop
		}
		maxAlignment = max(maxAlignment, reg.Type().Alignment())

		regionData, relocations := kFuzzTestExpandRegion(reg)
		for _, reloc := range relocations {
			if reloc.dstRegion == nil {
				continue
			}
			if _, visited := visitedRegions[reloc.dstRegion]; !visited {
				queue.push(reloc.dstRegion)
			}
		}
		allRelocations = append(allRelocations, relocations...)

		padWithAlignment(&payload, reg.Type().Alignment(), 0)
		regions = append(regions, kFuzzTestRegion{
			offset: uint32(payload.Len()),
			size:   uint32(len(regionData))},
		)
		visitedRegions[reg] = len(regions) - 1
		payload.Write(regionData)
		payload.Write(make([]byte, kFuzzTestPoisonSize)) // 8 bytes of padding.
	}

	regionArraySize := kFuzzTestRegionArraySize(len(regions))
	relocTableSize := kFuzzTestRelocTableSize(len(allRelocations))
	headerLen := regionArraySize + relocTableSize

	// The payload needs to be aligned to max alignment to ensure that all
	// nested structs are properly aligned, and there should be enough padding
	// so that the region before the payload can be poisoned with a redzone.
	paddingBytes := roundUpPowerOfTwo(uint64(headerLen)+kFuzzTestPoisonSize, maxAlignment) - uint64(headerLen)

	var out bytes.Buffer
	kFuzzTestWriteRegionArray(&out, regions)
	kFuzzTestWriteRelocTable(&out, &visitedRegions, allRelocations, paddingBytes)
	out.Write(payload.Bytes())
	return out.Bytes()
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
