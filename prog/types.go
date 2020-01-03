// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"strings"
)

type Syscall struct {
	ID          int
	NR          uint64 // kernel syscall number
	Name        string
	CallName    string
	MissingArgs int // number of trailing args that should be zero-filled
	Args        []Type
	Ret         Type

	inputResources  []*ResourceDesc
	outputResources []*ResourceDesc
}

type Dir int

const (
	DirIn Dir = iota
	DirOut
	DirInOut
)

func (dir Dir) String() string {
	switch dir {
	case DirIn:
		return "in"
	case DirOut:
		return "out"
	case DirInOut:
		return "inout"
	default:
		panic("unknown dir")
	}
}

type BinaryFormat int

const (
	FormatNative BinaryFormat = iota
	FormatBigEndian
	FormatStrDec
	FormatStrHex
	FormatStrOct
)

type Type interface {
	String() string
	Name() string
	FieldName() string
	TemplateName() string // for template structs name without arguments
	Dir() Dir
	Optional() bool
	Varlen() bool
	Size() uint64
	TypeBitSize() uint64
	Format() BinaryFormat
	BitfieldOffset() uint64
	BitfieldLength() uint64
	IsBitfield() bool
	// For most of the types UnitSize is equal to Size.
	// These are different only for all but last bitfield in the group,
	// where Size == 0 and UnitSize equals to the underlying bitfield type size.
	UnitSize() uint64
	UnitOffset() uint64

	DefaultArg() Arg
	isDefaultArg(arg Arg) bool
	generate(r *randGen, s *state) (arg Arg, calls []*Call)
	mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool)
	getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool)
	minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool
}

func IsPad(t Type) bool {
	if ct, ok := t.(*ConstType); ok && ct.IsPad {
		return true
	}
	return false
}

type TypeCommon struct {
	TypeName string
	FldName  string // for struct fields and named args
	// Static size of the type, or 0 for variable size types and all but last bitfields in the group.
	TypeSize   uint64
	ArgDir     Dir
	IsOptional bool
	IsVarlen   bool
}

func (t *TypeCommon) Name() string {
	return t.TypeName
}

func (t *TypeCommon) FieldName() string {
	return t.FldName
}

func (t *TypeCommon) TemplateName() string {
	name := t.TypeName
	if pos := strings.IndexByte(name, '['); pos != -1 {
		name = name[:pos]
	}
	return name
}

func (t *TypeCommon) Optional() bool {
	return t.IsOptional
}

func (t *TypeCommon) Size() uint64 {
	if t.IsVarlen {
		panic(fmt.Sprintf("static type size is not known: %#v", t))
	}
	return t.TypeSize
}

func (t *TypeCommon) TypeBitSize() uint64 {
	panic("cannot get the bitsize for a non-integer type")
}

func (t *TypeCommon) Varlen() bool {
	return t.IsVarlen
}

func (t *TypeCommon) Format() BinaryFormat {
	return FormatNative
}

func (t *TypeCommon) BitfieldOffset() uint64 {
	return 0
}

func (t *TypeCommon) BitfieldLength() uint64 {
	return 0
}

func (t *TypeCommon) UnitSize() uint64 {
	return t.Size()
}

func (t *TypeCommon) UnitOffset() uint64 {
	return 0
}

func (t *TypeCommon) IsBitfield() bool {
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
	Ctors  []ResourceCtor
}

type ResourceCtor struct {
	Call    int // Index in Target.Syscalls
	Precise bool
}

type ResourceType struct {
	TypeCommon
	ArgFormat BinaryFormat
	Desc      *ResourceDesc
}

func (t *ResourceType) String() string {
	return t.Name()
}

func (t *ResourceType) DefaultArg() Arg {
	return MakeResultArg(t, nil, t.Default())
}

func (t *ResourceType) isDefaultArg(arg Arg) bool {
	a := arg.(*ResultArg)
	return a.Res == nil && a.OpDiv == 0 && a.OpAdd == 0 &&
		len(a.uses) == 0 && a.Val == t.Default()
}

func (t *ResourceType) Default() uint64 {
	return t.Desc.Values[0]
}

func (t *ResourceType) SpecialValues() []uint64 {
	return t.Desc.Values
}

func (t *ResourceType) Format() BinaryFormat {
	return t.ArgFormat
}

type IntTypeCommon struct {
	TypeCommon
	ArgFormat       BinaryFormat
	BitfieldOff     uint64
	BitfieldLen     uint64
	BitfieldUnit    uint64
	BitfieldUnitOff uint64
}

func (t *IntTypeCommon) String() string {
	return t.Name()
}

func (t *IntTypeCommon) Format() BinaryFormat {
	return t.ArgFormat
}

// Returns the size in bits for integers in binary format or 64 for string-formatted integers. The return
// value is used in computing limits and truncating other values.
func (t *IntTypeCommon) TypeBitSize() uint64 {
	if t.ArgFormat != FormatNative && t.ArgFormat != FormatBigEndian {
		// TODO: add special cases for mutation and generation of string-formatted integers.
		return 64
	}
	if t.BitfieldLen != 0 {
		return t.BitfieldLen
	}
	return t.TypeSize * 8
}

func (t *IntTypeCommon) BitfieldOffset() uint64 {
	return t.BitfieldOff
}

func (t *IntTypeCommon) BitfieldLength() uint64 {
	return t.BitfieldLen
}

func (t *IntTypeCommon) UnitSize() uint64 {
	if t.BitfieldLen != 0 {
		return t.BitfieldUnit
	}
	return t.Size()
}

func (t *IntTypeCommon) UnitOffset() uint64 {
	return t.BitfieldUnitOff
}

func (t *IntTypeCommon) IsBitfield() bool {
	return t.BitfieldLen != 0
}

type ConstType struct {
	IntTypeCommon
	Val   uint64
	IsPad bool
}

func (t *ConstType) DefaultArg() Arg {
	return MakeConstArg(t, t.Val)
}

func (t *ConstType) isDefaultArg(arg Arg) bool {
	return arg.(*ConstArg).Val == t.Val
}

func (t *ConstType) String() string {
	if t.IsPad {
		return fmt.Sprintf("pad[%v]", t.Size())
	}
	return fmt.Sprintf("const[%v, %v]", t.Val, t.IntTypeCommon.String())
}

type IntKind int

const (
	IntPlain IntKind = iota
	IntRange
)

type IntType struct {
	IntTypeCommon
	Kind       IntKind
	RangeBegin uint64
	RangeEnd   uint64
	Align      uint64
}

func (t *IntType) DefaultArg() Arg {
	return MakeConstArg(t, 0)
}

func (t *IntType) isDefaultArg(arg Arg) bool {
	return arg.(*ConstArg).Val == 0
}

type FlagsType struct {
	IntTypeCommon
	Vals    []uint64
	BitMask bool
}

func (t *FlagsType) DefaultArg() Arg {
	return MakeConstArg(t, 0)
}

func (t *FlagsType) isDefaultArg(arg Arg) bool {
	return arg.(*ConstArg).Val == 0
}

type LenType struct {
	IntTypeCommon
	BitSize uint64 // want size in multiple of bits instead of array size
	Offset  bool   // offset from the beginning of the parent struct or base object
	Path    []string
}

func (t *LenType) DefaultArg() Arg {
	return MakeConstArg(t, 0)
}

func (t *LenType) isDefaultArg(arg Arg) bool {
	return arg.(*ConstArg).Val == 0
}

type ProcType struct {
	IntTypeCommon
	ValuesStart   uint64
	ValuesPerProc uint64
}

const (
	MaxPids          = 32
	procDefaultValue = 0xffffffffffffffff // special value denoting 0 for all procs
)

func (t *ProcType) DefaultArg() Arg {
	return MakeConstArg(t, procDefaultValue)
}

func (t *ProcType) isDefaultArg(arg Arg) bool {
	return arg.(*ConstArg).Val == procDefaultValue
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

func (t *CsumType) String() string {
	return "csum"
}

func (t *CsumType) DefaultArg() Arg {
	return MakeConstArg(t, 0)
}

func (t *CsumType) isDefaultArg(arg Arg) bool {
	return arg.(*ConstArg).Val == 0
}

type VmaType struct {
	TypeCommon
	RangeBegin uint64 // in pages
	RangeEnd   uint64
}

func (t *VmaType) String() string {
	return "vma"
}

func (t *VmaType) DefaultArg() Arg {
	return MakeSpecialPointerArg(t, 0)
}

func (t *VmaType) isDefaultArg(arg Arg) bool {
	a := arg.(*PointerArg)
	return a.IsSpecial() && a.Address == 0
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
	TextTarget TextKind = iota
	TextX86Real
	TextX86bit16
	TextX86bit32
	TextX86bit64
	TextArm64
)

type BufferType struct {
	TypeCommon
	Kind       BufferKind
	RangeBegin uint64   // for BufferBlobRange kind
	RangeEnd   uint64   // for BufferBlobRange kind
	Text       TextKind // for BufferText
	SubKind    string
	Values     []string // possible values for BufferString kind
	NoZ        bool     // non-zero terminated BufferString/BufferFilename
}

func (t *BufferType) String() string {
	return "buffer"
}

func (t *BufferType) DefaultArg() Arg {
	if t.Dir() == DirOut {
		var sz uint64
		if !t.Varlen() {
			sz = t.Size()
		}
		return MakeOutDataArg(t, sz)
	}
	var data []byte
	if !t.Varlen() {
		data = make([]byte, t.Size())
	}
	return MakeDataArg(t, data)
}

func (t *BufferType) isDefaultArg(arg Arg) bool {
	a := arg.(*DataArg)
	if a.Size() == 0 {
		return true
	}
	if a.Type().Varlen() {
		return false
	}
	if a.Type().Dir() == DirOut {
		return true
	}
	for _, v := range a.Data() {
		if v != 0 {
			return false
		}
	}
	return true
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

func (t *ArrayType) String() string {
	return fmt.Sprintf("array[%v]", t.Type.String())
}

func (t *ArrayType) DefaultArg() Arg {
	var elems []Arg
	if t.Kind == ArrayRangeLen && t.RangeBegin == t.RangeEnd {
		for i := uint64(0); i < t.RangeBegin; i++ {
			elems = append(elems, t.Type.DefaultArg())
		}
	}
	return MakeGroupArg(t, elems)
}

func (t *ArrayType) isDefaultArg(arg Arg) bool {
	a := arg.(*GroupArg)
	if !a.fixedInnerSize() && len(a.Inner) != 0 {
		return false
	}
	for _, elem := range a.Inner {
		if !isDefault(elem) {
			return false
		}
	}
	return true
}

type PtrType struct {
	TypeCommon
	Type Type
}

func (t *PtrType) String() string {
	return fmt.Sprintf("ptr[%v, %v]", t.Dir(), t.Type.String())
}

func (t *PtrType) DefaultArg() Arg {
	if t.Optional() {
		return MakeSpecialPointerArg(t, 0)
	}
	return MakePointerArg(t, 0, t.Type.DefaultArg())
}

func (t *PtrType) isDefaultArg(arg Arg) bool {
	a := arg.(*PointerArg)
	if t.Optional() {
		return a.IsSpecial() && a.Address == 0
	}
	return a.Address == 0 && a.Res != nil && isDefault(a.Res)
}

type StructType struct {
	Key     StructKey
	FldName string
	*StructDesc
}

func (t *StructType) String() string {
	return t.Name()
}

func (t *StructType) FieldName() string {
	return t.FldName
}

func (t *StructType) DefaultArg() Arg {
	inner := make([]Arg, len(t.Fields))
	for i, field := range t.Fields {
		inner[i] = field.DefaultArg()
	}
	return MakeGroupArg(t, inner)
}

func (t *StructType) isDefaultArg(arg Arg) bool {
	a := arg.(*GroupArg)
	for _, elem := range a.Inner {
		if !isDefault(elem) {
			return false
		}
	}
	return true
}

type UnionType struct {
	Key     StructKey
	FldName string
	*StructDesc
}

func (t *UnionType) String() string {
	return t.Name()
}

func (t *UnionType) FieldName() string {
	return t.FldName
}

func (t *UnionType) DefaultArg() Arg {
	return MakeUnionArg(t, t.Fields[0].DefaultArg())
}

func (t *UnionType) isDefaultArg(arg Arg) bool {
	a := arg.(*UnionArg)
	return a.Option.Type().FieldName() == t.Fields[0].FieldName() && isDefault(a.Option)
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
