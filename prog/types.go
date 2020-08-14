// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"strings"
	"unicode"
)

type Syscall struct {
	ID          int
	NR          uint64 // kernel syscall number
	Name        string
	CallName    string
	MissingArgs int // number of trailing args that should be zero-filled
	Args        []Field
	Ret         Type
	Attrs       SyscallAttrs

	inputResources  []*ResourceDesc
	outputResources []*ResourceDesc
}

// SyscallAttrs represents call attributes in syzlang.
//
// This structure is the source of truth for the all other parts of the system.
// pkg/compiler uses this structure to parse descriptions.
// syz-sysgen uses this structure to generate code for executor.
//
// Only bool's and uint64's are currently supported.
//
// See docs/syscall_descriptions_syntax.md for description of individual attributes.
type SyscallAttrs struct {
	Disabled      bool
	Timeout       uint64
	ProgTimeout   uint64
	IgnoreReturn  bool
	BreaksReturns bool
}

// MaxArgs is maximum number of syscall arguments.
// Executor also knows about this value.
const MaxArgs = 9

type Dir uint8

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

type Field struct {
	Name string
	Type
	HasDirection bool
	Direction    Dir
}

func (f *Field) Dir(def Dir) Dir {
	if f.HasDirection {
		return f.Direction
	}
	return def
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
	TemplateName() string // for template structs name without arguments
	Optional() bool
	Varlen() bool
	Size() uint64
	TypeBitSize() uint64
	Alignment() uint64
	Format() BinaryFormat
	BitfieldOffset() uint64
	BitfieldLength() uint64
	IsBitfield() bool
	// For most of the types UnitSize is equal to Size.
	// These are different only for all but last bitfield in the group,
	// where Size == 0 and UnitSize equals to the underlying bitfield type size.
	UnitSize() uint64
	UnitOffset() uint64

	DefaultArg(dir Dir) Arg
	isDefaultArg(arg Arg) bool
	generate(r *randGen, s *state, dir Dir) (arg Arg, calls []*Call)
	mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool)
	getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool)
	minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool
	ref() Ref
	setRef(ref Ref)
}

type Ref uint32

func (ti Ref) String() string       { panic("prog.Ref method called") }
func (ti Ref) Name() string         { panic("prog.Ref method called") }
func (ti Ref) TemplateName() string { panic("prog.Ref method called") }

func (ti Ref) Optional() bool                                        { panic("prog.Ref method called") }
func (ti Ref) Varlen() bool                                          { panic("prog.Ref method called") }
func (ti Ref) Size() uint64                                          { panic("prog.Ref method called") }
func (ti Ref) TypeBitSize() uint64                                   { panic("prog.Ref method called") }
func (ti Ref) Alignment() uint64                                     { panic("prog.Ref method called") }
func (ti Ref) Format() BinaryFormat                                  { panic("prog.Ref method called") }
func (ti Ref) BitfieldOffset() uint64                                { panic("prog.Ref method called") }
func (ti Ref) BitfieldLength() uint64                                { panic("prog.Ref method called") }
func (ti Ref) IsBitfield() bool                                      { panic("prog.Ref method called") }
func (ti Ref) UnitSize() uint64                                      { panic("prog.Ref method called") }
func (ti Ref) UnitOffset() uint64                                    { panic("prog.Ref method called") }
func (ti Ref) DefaultArg(dir Dir) Arg                                { panic("prog.Ref method called") }
func (ti Ref) Clone() Type                                           { panic("prog.Ref method called") }
func (ti Ref) isDefaultArg(arg Arg) bool                             { panic("prog.Ref method called") }
func (ti Ref) generate(r *randGen, s *state, dir Dir) (Arg, []*Call) { panic("prog.Ref method called") }
func (ti Ref) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) ([]*Call, bool, bool) {
	panic("prog.Ref method called")
}
func (ti Ref) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (float64, bool) {
	panic("prog.Ref method called")
}
func (ti Ref) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	panic("prog.Ref method called")
}
func (ti Ref) ref() Ref       { panic("prog.Ref method called") }
func (ti Ref) setRef(ref Ref) { panic("prog.Ref method called") }

func IsPad(t Type) bool {
	if ct, ok := t.(*ConstType); ok && ct.IsPad {
		return true
	}
	return false
}

type TypeCommon struct {
	TypeName string
	// Static size of the type, or 0 for variable size types and all but last bitfields in the group.
	TypeSize   uint64
	TypeAlign  uint64
	IsOptional bool
	IsVarlen   bool

	self Ref
}

func (t *TypeCommon) Name() string {
	return t.TypeName
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

func (t *TypeCommon) ref() Ref {
	if t.self == 0 {
		panic("ref is not assigned yet")
	}
	return t.self
}

func (t *TypeCommon) setRef(ref Ref) {
	t.self = ref
}

func (t *TypeCommon) Alignment() uint64 {
	return t.TypeAlign
}

type ResourceDesc struct {
	Name   string
	Kind   []string
	Values []uint64
	Ctors  []ResourceCtor
}

type ResourceCtor struct {
	Call    int // index in Target.Syscalls
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

func (t *ResourceType) DefaultArg(dir Dir) Arg {
	return MakeResultArg(t, dir, nil, t.Default())
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

func (t *ConstType) DefaultArg(dir Dir) Arg {
	return MakeConstArg(t, dir, t.Val)
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

func (t *IntType) DefaultArg(dir Dir) Arg {
	return MakeConstArg(t, dir, 0)
}

func (t *IntType) isDefaultArg(arg Arg) bool {
	return arg.(*ConstArg).Val == 0
}

type FlagsType struct {
	IntTypeCommon
	Vals    []uint64 // compiler ensures that it's not empty
	BitMask bool
}

func (t *FlagsType) DefaultArg(dir Dir) Arg {
	return MakeConstArg(t, dir, 0)
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

func (t *LenType) DefaultArg(dir Dir) Arg {
	return MakeConstArg(t, dir, 0)
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

func (t *ProcType) DefaultArg(dir Dir) Arg {
	return MakeConstArg(t, dir, procDefaultValue)
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

func (t *CsumType) DefaultArg(dir Dir) Arg {
	return MakeConstArg(t, dir, 0)
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

func (t *VmaType) DefaultArg(dir Dir) Arg {
	return MakeSpecialPointerArg(t, dir, 0)
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

func (t *BufferType) DefaultArg(dir Dir) Arg {
	if dir == DirOut {
		var sz uint64
		if !t.Varlen() {
			sz = t.Size()
		}
		return MakeOutDataArg(t, dir, sz)
	}
	var data []byte
	if !t.Varlen() {
		data = make([]byte, t.Size())
	}
	return MakeDataArg(t, dir, data)
}

func (t *BufferType) isDefaultArg(arg Arg) bool {
	a := arg.(*DataArg)
	if a.Size() == 0 {
		return true
	}
	if a.Type().Varlen() {
		return false
	}
	if a.Dir() == DirOut {
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
	Elem       Type
	Kind       ArrayKind
	RangeBegin uint64
	RangeEnd   uint64
}

func (t *ArrayType) String() string {
	return fmt.Sprintf("array[%v]", t.Elem.String())
}

func (t *ArrayType) DefaultArg(dir Dir) Arg {
	var elems []Arg
	if t.Kind == ArrayRangeLen && t.RangeBegin == t.RangeEnd {
		for i := uint64(0); i < t.RangeBegin; i++ {
			elems = append(elems, t.Elem.DefaultArg(dir))
		}
	}
	return MakeGroupArg(t, dir, elems)
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
	Elem    Type
	ElemDir Dir
}

func (t *PtrType) String() string {
	return fmt.Sprintf("ptr[%v, %v]", t.ElemDir, t.Elem.String())
}

func (t *PtrType) DefaultArg(dir Dir) Arg {
	if t.Optional() {
		return MakeSpecialPointerArg(t, dir, 0)
	}
	return MakePointerArg(t, dir, 0, t.Elem.DefaultArg(t.ElemDir))
}

func (t *PtrType) isDefaultArg(arg Arg) bool {
	a := arg.(*PointerArg)
	if t.Optional() {
		return a.IsSpecial() && a.Address == 0
	}
	return a.Address == 0 && a.Res != nil && isDefault(a.Res)
}

type StructType struct {
	TypeCommon
	Fields    []Field
	AlignAttr uint64
}

func (t *StructType) String() string {
	return t.Name()
}

func (t *StructType) DefaultArg(dir Dir) Arg {
	inner := make([]Arg, len(t.Fields))
	for i, field := range t.Fields {
		inner[i] = field.DefaultArg(field.Dir(dir))
	}
	return MakeGroupArg(t, dir, inner)
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
	TypeCommon
	Fields []Field
}

func (t *UnionType) String() string {
	return t.Name()
}

func (t *UnionType) DefaultArg(dir Dir) Arg {
	f := t.Fields[0]
	return MakeUnionArg(t, dir, f.DefaultArg(f.Dir(dir)), 0)
}

func (t *UnionType) isDefaultArg(arg Arg) bool {
	a := arg.(*UnionArg)
	return a.Index == 0 && isDefault(a.Option)
}

type ConstValue struct {
	Name  string
	Value uint64
}

type TypeCtx struct {
	Meta *Syscall
	Dir  Dir
	Ptr  *Type
}

func ForeachType(syscalls []*Syscall, f func(t Type, ctx TypeCtx)) {
	for _, meta := range syscalls {
		foreachTypeImpl(meta, true, f)
	}
}

func ForeachTypePost(syscalls []*Syscall, f func(t Type, ctx TypeCtx)) {
	for _, meta := range syscalls {
		foreachTypeImpl(meta, false, f)
	}
}

func ForeachCallType(meta *Syscall, f func(t Type, ctx TypeCtx)) {
	foreachTypeImpl(meta, true, f)
}

func foreachTypeImpl(meta *Syscall, preorder bool, f func(t Type, ctx TypeCtx)) {
	// Note: we specifically don't create seen in ForeachType.
	// It would prune recursion more (across syscalls), but lots of users need to
	// visit each struct per-syscall (e.g. prio, used resources).
	seen := make(map[Type]bool)
	var rec func(*Type, Dir)
	rec = func(ptr *Type, dir Dir) {
		if preorder {
			f(*ptr, TypeCtx{Meta: meta, Dir: dir, Ptr: ptr})
		}
		switch a := (*ptr).(type) {
		case *PtrType:
			rec(&a.Elem, a.ElemDir)
		case *ArrayType:
			rec(&a.Elem, dir)
		case *StructType:
			if seen[a] {
				break // prune recursion via pointers to structs/unions
			}
			seen[a] = true
			for i, f := range a.Fields {
				rec(&a.Fields[i].Type, f.Dir(dir))
			}
		case *UnionType:
			if seen[a] {
				break // prune recursion via pointers to structs/unions
			}
			seen[a] = true
			for i, f := range a.Fields {
				rec(&a.Fields[i].Type, f.Dir(dir))
			}
		case *ResourceType, *BufferType, *VmaType, *LenType, *FlagsType,
			*ConstType, *IntType, *ProcType, *CsumType:
		case Ref:
			// This is only needed for pkg/compiler.
		default:
			panic("unknown type")
		}
		if !preorder {
			f(*ptr, TypeCtx{Meta: meta, Dir: dir, Ptr: ptr})
		}
	}
	for i := range meta.Args {
		rec(&meta.Args[i].Type, DirIn)
	}
	if meta.Ret != nil {
		rec(&meta.Ret, DirOut)
	}
}

// CppName transforms PascalStyleNames to cpp_style_names.
func CppName(name string) string {
	var res []byte
	for i := range name {
		c := rune(name[i])
		if unicode.IsUpper(c) && i != 0 && !unicode.IsUpper(rune(name[i-1])) {
			res = append(res, '_')
		}
		res = append(res, byte(unicode.ToLower(c)))
	}
	return string(res)
}
