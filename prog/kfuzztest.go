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

func kFuzzTestWriteReloc(buf *bytes.Buffer, regToId *map[Arg]int, reloc kFuzzTestRelocation) {
	binary.Write(buf, binary.LittleEndian, uint32((*regToId)[reloc.srcRegion]))
	binary.Write(buf, binary.LittleEndian, reloc.offset)
	if reloc.dstRegion == nil {
		binary.Write(buf, binary.LittleEndian, kFuzzTestRegionIDNull)
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

const kFuzzTestPlaceHolderPtr uint64 = 0xFFFFFFFFFFFFFFFF

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
			binary.Write(&encoded, binary.LittleEndian, kFuzzTestPlaceHolderPtr)
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

	prefixSize := 0x8 // Prefix is always 8-bytes.
	regionArraySize := kFuzzTestRegionArraySize(len(regions))
	relocTableSize := kFuzzTestRelocTableSize(len(allRelocations))
	headerLen := prefixSize + regionArraySize + relocTableSize

	// The payload needs to be aligned to max alignment to ensure that all
	// nested structs are properly aligned, and there should be enough padding
	// so that the region before the payload can be poisoned with a redzone.
	paddingBytes := roundUpPowerOfTwo(uint64(headerLen)+kFuzzTestPoisonSize, maxAlignment) - uint64(headerLen)

	var out bytes.Buffer
	kFuzzTestWritePrefix(&out)
	kFuzzTestWriteRegionArray(&out, regions)
	kFuzzTestWriteRelocTable(&out, &visitedRegions, allRelocations, paddingBytes)
	out.Write(payload.Bytes())
	return out.Bytes()
}
