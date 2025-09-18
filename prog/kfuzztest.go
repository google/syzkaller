// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package prog

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	kFuzzTestRegionIDNull uint32 = ^uint32(0)
	kFuzzTestPoisonSize   uint64 = 0x8

	kFuzzTestVersion    uint32 = 0
	kFuzzTestMagic      uint32 = 0xBFACE
	kFuzzTestPrefixSize        = 8

	// Minimum region alignment required by KFuzzTest. This is exposed by the
	// /sys/kernel/debug/kfuzztest/_config/minalign debugfs file. This value
	// always equals MAX(ARCH_KMALLOC_MINALIGN, KFUZZTEST_POISON_SIZE) = 8 on
	// x86_64, so we hardcode it for now. A more robust solution would involve
	// reading this from the debugfs entry at boot before fuzzing begins.
	kFuzzTestMinalign uint64 = 8

	// Maximum input size accepted by the KFuzzTest kernel module.
	KFuzzTestMaxInputSize uint64 = 64 << 10
)

func kFuzzTestWritePrefix(buf *bytes.Buffer) {
	prefix := (uint64(kFuzzTestVersion) << 32) | uint64(kFuzzTestMagic)
	binary.Write(buf, binary.LittleEndian, prefix)
}

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

func kFuzzTestWriteReloc(buf *bytes.Buffer, regToID *map[Arg]int, reloc kFuzzTestRelocation) {
	binary.Write(buf, binary.LittleEndian, uint32((*regToID)[reloc.srcRegion]))
	binary.Write(buf, binary.LittleEndian, reloc.offset)
	if reloc.dstRegion == nil {
		binary.Write(buf, binary.LittleEndian, kFuzzTestRegionIDNull)
	} else {
		binary.Write(buf, binary.LittleEndian, uint32((*regToID)[reloc.dstRegion]))
	}
}

func kFuzzTestWriteRelocTable(buf *bytes.Buffer, regToID *map[Arg]int,
	relocations []kFuzzTestRelocation, paddingBytes uint64) {
	binary.Write(buf, binary.LittleEndian, uint32(len(relocations)))
	binary.Write(buf, binary.LittleEndian, uint32(paddingBytes))
	for _, reloc := range relocations {
		kFuzzTestWriteReloc(buf, regToID, reloc)
	}
	buf.Write(make([]byte, paddingBytes))
}

const kFuzzTestPlaceHolderPtr uint64 = 0xFFFFFFFFFFFFFFFF

// Expands a region, and returns a list of relocations that need to be made.
func kFuzzTestExpandRegion(reg Arg) ([]byte, []kFuzzTestRelocation) {
	relocations := []kFuzzTestRelocation{}
	var encoded bytes.Buffer
	queue := newSliceQueue[Arg]()
	queue.push(reg)

	for !queue.isEmpty() {
		arg := queue.pop()
		padWithAlignment(&encoded, arg.Type().Alignment(), 0)

		switch a := arg.(type) {
		case *PointerArg:
			offset := uint32(encoded.Len())
			binary.Write(&encoded, binary.LittleEndian, kFuzzTestPlaceHolderPtr)
			relocations = append(relocations, kFuzzTestRelocation{offset, reg, a.Res})
		case *GroupArg:
			for _, inner := range a.Inner {
				queue.push(inner)
			}
		case *DataArg:
			data := a.data
			buffer, ok := a.ArgCommon.Type().(*BufferType)
			if !ok {
				panic("DataArg should be a BufferType")
			}
			// Unlike length fields whose incorrectness can be prevented easily,
			// it is an invasive change to prevent generation of
			// non-null-terminated strings. Forcibly null-terminating them
			// during encoding allows us to centralize this easily and prevent
			// false positive buffer overflows in KFuzzTest targets.
			if buffer.Kind == BufferString && (len(data) == 0 || data[len(data)-1] != byte(0)) {
				data = append(data, byte(0))
			}
			encoded.Write(data)
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
				binary.Write(&encoded, binary.LittleEndian, val)
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

// MarshallKFuzzTestArg serializes a syzkaller Arg into a flat binary format
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
//     contiguous block of memory with padded regions as per the KFuzzTest input
//     format's specification defined in `Documentation/dev-tools/kfuzztest.rst`.
//
// Cycles are handled by tracking visited arguments, ensuring that a region is
// only visited and encoded once.
//
// For a concrete example of the final binary layout, see the test cases for this
// function in `prog/kfuzztest_test.go`.
func MarshallKFuzztestArg(topLevel Arg) []byte {
	regions := []kFuzzTestRegion{}
	allRelocations := []kFuzzTestRelocation{}
	visitedRegions := make(map[Arg]int)
	queue := newSliceQueue[Arg]()
	var payload bytes.Buffer
	queue.push(topLevel)
	maxAlignment := uint64(8)

	if topLevel == nil {
		return []byte{}
	}

Loop:
	for {
		if queue.isEmpty() {
			break Loop
		}

		reg := queue.pop()
		if _, visited := visitedRegions[reg]; visited {
			continue Loop
		}

		alignment := max(kFuzzTestMinalign, reg.Type().Alignment())
		maxAlignment = max(maxAlignment, alignment)

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

		padWithAlignment(&payload, alignment, 0)
		regions = append(regions, kFuzzTestRegion{
			offset: uint32(payload.Len()),
			size:   uint32(len(regionData))},
		)
		visitedRegions[reg] = len(regions) - 1
		payload.Write(regionData)
		// The end of the payload should have at least kFuzzTestPoisonSize bytes
		// of padding, and be aligned to kFuzzTestPoisonSize.
		padWithAlignment(&payload, kFuzzTestPoisonSize, kFuzzTestPoisonSize)
	}

	headerLen := 0x8 // Two integer values - the magic value, and the version number.
	regionArrayLen := kFuzzTestRegionArraySize(len(regions))
	relocTableLen := kFuzzTestRelocTableSize(len(allRelocations))
	metadataLen := headerLen + regionArrayLen + relocTableLen

	// The payload needs to be aligned to max alignment to ensure that all
	// nested structs are properly aligned, and there should be enough padding
	// so that the region before the payload can be poisoned with a redzone.
	paddingBytes := roundUpPowerOfTwo(uint64(metadataLen)+kFuzzTestPoisonSize, maxAlignment) - uint64(metadataLen)

	var out bytes.Buffer
	kFuzzTestWritePrefix(&out)
	kFuzzTestWriteRegionArray(&out, regions)
	kFuzzTestWriteRelocTable(&out, &visitedRegions, allRelocations, paddingBytes)
	out.Write(payload.Bytes())
	return out.Bytes()
}
