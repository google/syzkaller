package kfuzztest

import "debug/elf"

// The parsableFromBytes interface describes a kftf object that can be parsed
// from a vmlinux binary. All objects are expected to satisfy the following
// constraints
//   - Must be statically sized. I.e. the size() function should return some
//     fixed value
//   - Densely packed: size must exactly describe the number of bytes between
//     the start address of instance i and that of instance i+1.
//
// No further assumptions are made about the semantics of the object. For
// example if some field is a pointer to a string (*const char) this will not
// be read from the binary. This responsibility is offloaded to the caller.
type parsableFromBytes interface {
	fromBytes(elfFile *elf.File, data []byte)
	size() uint64
	startSymbol() string
	endSymbol() string
}

type kftfTestCase struct {
	name    uint64
	argType uint64
	writeCb uint64
	readCb  uint64
}

const kftfSectionStart string = "__kfuzztest_targets_start"
const kftfSectionEnd string = "__kfuzztest_targets_end"
const kfuzzTestSize uint64 = 32

func (tc *kftfTestCase) fromBytes(elfFile *elf.File, data []byte) {
	tc.name = elfFile.ByteOrder.Uint64(data[0:8])
	tc.argType = elfFile.ByteOrder.Uint64(data[8:16])
	tc.writeCb = elfFile.ByteOrder.Uint64(data[16:24])
	tc.readCb = elfFile.ByteOrder.Uint64(data[24:32])
}

func (tc *kftfTestCase) size() uint64 {
	return kfuzzTestSize
}

func (tc *kftfTestCase) startSymbol() string {
	return kftfSectionStart
}

func (tc *kftfTestCase) endSymbol() string {
	return kftfSectionEnd
}

type kftfConstraint struct {
	inputType      uint64
	fieldName      uint64
	value1         uintptr
	value2         uintptr
	constraintType uint8
}

const kftfConstraintStart string = "__kfuzztest_constraints_start"
const kftfConstraintEnd string = "__kfuzztest_constraints_end"
const kftfConstraintSize uint64 = 64

func (c *kftfConstraint) fromBytes(elfFile *elf.File, data []byte) {
	constraintTypeBytes := elfFile.ByteOrder.Uint64(data[32:40])
	c.inputType = elfFile.ByteOrder.Uint64(data[0:8])
	c.fieldName = elfFile.ByteOrder.Uint64(data[8:16])
	c.value1 = uintptr(elfFile.ByteOrder.Uint64(data[16:24]))
	c.value2 = uintptr(elfFile.ByteOrder.Uint64(data[24:32]))
	c.constraintType = uint8(constraintTypeBytes & 0xFF)
}

func (tc *kftfConstraint) size() uint64 {
	return kftfConstraintSize
}

func (tc *kftfConstraint) startSymbol() string {
	return kftfConstraintStart
}

func (tc *kftfConstraint) endSymbol() string {
	return kftfConstraintEnd
}

type kftfAnnotation struct {
	inputType           uint64
	fieldName           uint64
	linkedFieldName     uint64
	annotationAttribute uint8
}

func (a *kftfAnnotation) fromBytes(elfFile *elf.File, data []byte) {
	a.inputType = elfFile.ByteOrder.Uint64(data[0:8])
	a.fieldName = elfFile.ByteOrder.Uint64(data[8:16])
	a.linkedFieldName = elfFile.ByteOrder.Uint64(data[16:24])
	a.annotationAttribute = uint8(data[24])
}

const kftfAnnotationStart string = "__kfuzztest_annotations_start"
const kftfAnnotationEnd string = "__kfuzztest_annotations_end"
const kftfAnnotationSize uint64 = 32

func (attrib *kftfAnnotation) size() uint64 {
	return kftfAnnotationSize
}

func (attrib *kftfAnnotation) startSymbol() string {
	return kftfAnnotationStart
}

func (attrib *kftfAnnotation) endSymbol() string {
	return kftfAnnotationEnd
}
