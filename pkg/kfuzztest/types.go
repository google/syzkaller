// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package kfuzztest

import (
	"debug/elf"
	"fmt"
)

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
	fromBytes(elfFile *elf.File, data []byte) error
	size() uint64
	startSymbol() string
	endSymbol() string
}

type kfuzztestTarget struct {
	name    uint64
	argType uint64
	writeCb uint64
	readCb  uint64
}

const kfuzztestTargetStart string = "__kfuzztest_targets_start"
const kfuzztestTargetEnd string = "__kfuzztest_targets_end"
const kfuzztestTargetSize uint64 = 32

func incorrectByteSizeErr(expected, actual uint64) error {
	return fmt.Errorf("incorrect number of bytes: expected %d, got %d", expected, actual)
}

func (targ *kfuzztestTarget) fromBytes(elfFile *elf.File, data []byte) error {
	if targ.size() != uint64(len(data)) {
		return incorrectByteSizeErr(targ.size(), uint64(len(data)))
	}
	targ.name = elfFile.ByteOrder.Uint64(data[0:8])
	targ.argType = elfFile.ByteOrder.Uint64(data[8:16])
	targ.writeCb = elfFile.ByteOrder.Uint64(data[16:24])
	targ.readCb = elfFile.ByteOrder.Uint64(data[24:32])
	return nil
}

func (targ *kfuzztestTarget) size() uint64 {
	return kfuzztestTargetSize
}

func (targ *kfuzztestTarget) startSymbol() string {
	return kfuzztestTargetStart
}

func (targ *kfuzztestTarget) endSymbol() string {
	return kfuzztestTargetEnd
}

type kfuzztestConstraint struct {
	inputType      uint64
	fieldName      uint64
	value1         uintptr
	value2         uintptr
	constraintType uint8
}

const kfuzztestConstraintStart string = "__kfuzztest_constraints_start"
const kfuzztestConstraintEnd string = "__kfuzztest_constraints_end"
const kfuzztestConstraintSize uint64 = 64

func (c *kfuzztestConstraint) fromBytes(elfFile *elf.File, data []byte) error {
	if c.size() != uint64(len(data)) {
		return incorrectByteSizeErr(c.size(), uint64(len(data)))
	}
	constraintTypeBytes := elfFile.ByteOrder.Uint64(data[32:40])
	c.inputType = elfFile.ByteOrder.Uint64(data[0:8])
	c.fieldName = elfFile.ByteOrder.Uint64(data[8:16])
	c.value1 = uintptr(elfFile.ByteOrder.Uint64(data[16:24]))
	c.value2 = uintptr(elfFile.ByteOrder.Uint64(data[24:32]))
	c.constraintType = uint8(constraintTypeBytes & 0xFF)
	return nil
}

func (c *kfuzztestConstraint) size() uint64 {
	return kfuzztestConstraintSize
}

func (c *kfuzztestConstraint) startSymbol() string {
	return kfuzztestConstraintStart
}

func (c *kfuzztestConstraint) endSymbol() string {
	return kfuzztestConstraintEnd
}

type kfuzztestAnnotation struct {
	inputType           uint64
	fieldName           uint64
	linkedFieldName     uint64
	annotationAttribute uint8
}

func (a *kfuzztestAnnotation) fromBytes(elfFile *elf.File, data []byte) error {
	if a.size() != uint64(len(data)) {
		return incorrectByteSizeErr(a.size(), uint64(len(data)))
	}
	a.inputType = elfFile.ByteOrder.Uint64(data[0:8])
	a.fieldName = elfFile.ByteOrder.Uint64(data[8:16])
	a.linkedFieldName = elfFile.ByteOrder.Uint64(data[16:24])
	a.annotationAttribute = data[24]
	return nil
}

const kftfAnnotationStart string = "__kfuzztest_annotations_start"
const kftfAnnotationEnd string = "__kfuzztest_annotations_end"
const kftfAnnotationSize uint64 = 32

func (a *kfuzztestAnnotation) size() uint64 {
	return kftfAnnotationSize
}

func (a *kfuzztestAnnotation) startSymbol() string {
	return kftfAnnotationStart
}

func (a *kfuzztestAnnotation) endSymbol() string {
	return kftfAnnotationEnd
}
