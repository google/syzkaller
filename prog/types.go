// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

type Syscall struct {
	ID       int
	NR       uint64 // kernel syscall number
	Name     string
	CallName string
	Args     []Type
	Ret      Type
}

type Dir int

const (
	DirIn Dir = iota
	DirOut
	DirInOut
)

type Type interface {
	Name() string
	FieldName() string
	Dir() Dir
	Optional() bool
	Default() uint64
	Varlen() bool
	Size() uint64
	BitfieldOffset() uint64
	BitfieldLength() uint64
	BitfieldMiddle() bool // returns true for all but last bitfield in a group
}

func IsPad(t Type) bool {
	if ct, ok := t.(*ConstType); ok && ct.IsPad {
		return true
	}
	return false
}

type TypeCommon struct {
	TypeName   string
	FldName    string // for struct fields and named args
	TypeSize   uint64 // static size of the type, or 0 for variable size types
	ArgDir     Dir
	IsOptional bool
}

func (t *TypeCommon) Name() string {
	return t.TypeName
}

func (t *TypeCommon) FieldName() string {
	return t.FldName
}

func (t *TypeCommon) Optional() bool {
	return t.IsOptional
}

func (t *TypeCommon) Default() uint64 {
	return 0
}

func (t *TypeCommon) Size() uint64 {
	if t.Varlen() {
		panic(fmt.Sprintf("static type size is not known: %#v", t))
	}
	return t.TypeSize
}

func (t *TypeCommon) Varlen() bool {
	return t.TypeSize == 0
}

func (t *TypeCommon) BitfieldOffset() uint64 {
	return 0
}

func (t *TypeCommon) BitfieldLength() uint64 {
	return 0
}

func (t *TypeCommon) BitfieldMiddle() bool {
	return false
}

func (t TypeCommon) Dir() Dir {
	return t.ArgDir
}

type ResourceDesc struct {
	Name   string
	Type   Type
	Kind   []string
	Values []uint64
}

type ResourceType struct {
	TypeCommon
	Desc *ResourceDesc
}

func (t *ResourceType) Default() uint64 {
	return t.Desc.Values[0]
}

func (t *ResourceType) SpecialValues() []uint64 {
	return t.Desc.Values
}

type IntTypeCommon struct {
	TypeCommon
	BitfieldOff uint64
	BitfieldLen uint64
	BigEndian   bool
	BitfieldMdl bool
}

func (t *IntTypeCommon) BitfieldOffset() uint64 {
	return t.BitfieldOff
}

func (t *IntTypeCommon) BitfieldLength() uint64 {
	return t.BitfieldLen
}

func (t *IntTypeCommon) BitfieldMiddle() bool {
	return t.BitfieldMdl
}

type ConstType struct {
	IntTypeCommon
	Val   uint64
	IsPad bool
}

type IntKind int

const (
	IntPlain   IntKind = iota
	IntFileoff         // offset within a file
	IntRange
)

type IntType struct {
	IntTypeCommon
	Kind       IntKind
	RangeBegin uint64
	RangeEnd   uint64
}

type FlagsType struct {
	IntTypeCommon
	Vals []uint64
}

type LenType struct {
	IntTypeCommon
	ByteSize uint64 // want size in multiple of bytes instead of array size
	Buf      string
}

type ProcType struct {
	IntTypeCommon
	ValuesStart   uint64
	ValuesPerProc uint64
}

type CsumKind int

const (
	CsumInet CsumKind = iota
	CsumPseudo
)

type CsumType struct {
	IntTypeCommon
	Kind     CsumKind
	Buf      string
	Protocol uint64 // for CsumPseudo
}

type VmaType struct {
	TypeCommon
	RangeBegin uint64 // in pages
	RangeEnd   uint64
}

type BufferKind int

const (
	BufferBlobRand BufferKind = iota
	BufferBlobRange
	BufferString
	BufferFilename
	BufferText
)

type TextKind int

const (
	Text_x86_real TextKind = iota
	Text_x86_16
	Text_x86_32
	Text_x86_64
	Text_arm64
)

type BufferType struct {
	TypeCommon
	Kind       BufferKind
	RangeBegin uint64   // for BufferBlobRange kind
	RangeEnd   uint64   // for BufferBlobRange kind
	Text       TextKind // for BufferText
	SubKind    string
	Values     []string // possible values for BufferString kind
}

type ArrayKind int

const (
	ArrayRandLen ArrayKind = iota
	ArrayRangeLen
)

type ArrayType struct {
	TypeCommon
	Type       Type
	Kind       ArrayKind
	RangeBegin uint64
	RangeEnd   uint64
}

type PtrType struct {
	TypeCommon
	Type Type
}

type StructType struct {
	Key     StructKey
	FldName string
	*StructDesc
}

func (t *StructType) FieldName() string {
	return t.FldName
}

type UnionType struct {
	Key     StructKey
	FldName string
	*StructDesc
}

func (t *UnionType) FieldName() string {
	return t.FldName
}

type StructDesc struct {
	TypeCommon
	Fields    []Type
	AlignAttr uint64
}

func (t *StructDesc) FieldName() string {
	panic("must not be called")
}

type StructKey struct {
	Name string
	Dir  Dir
}

type KeyedStruct struct {
	Key  StructKey
	Desc *StructDesc
}

type ConstValue struct {
	Name  string
	Value uint64
}

func ForeachType(meta *Syscall, f func(Type)) {
	seen := make(map[*StructDesc]bool)
	var rec func(t Type)
	rec = func(t Type) {
		f(t)
		switch a := t.(type) {
		case *PtrType:
			rec(a.Type)
		case *ArrayType:
			rec(a.Type)
		case *StructType:
			if seen[a.StructDesc] {
				return // prune recursion via pointers to structs/unions
			}
			seen[a.StructDesc] = true
			for _, f := range a.Fields {
				rec(f)
			}
		case *UnionType:
			if seen[a.StructDesc] {
				return // prune recursion via pointers to structs/unions
			}
			seen[a.StructDesc] = true
			for _, opt := range a.Fields {
				rec(opt)
			}
		case *ResourceType, *BufferType, *VmaType, *LenType,
			*FlagsType, *ConstType, *IntType, *ProcType, *CsumType:
		default:
			panic("unknown type")
		}
	}
	for _, t := range meta.Args {
		rec(t)
	}
	if meta.Ret != nil {
		rec(meta.Ret)
	}
}
