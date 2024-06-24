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

	// Resources that are required for this call to be generated (in/inout).
	inputResources []*ResourceDesc
	// Resources that this call can be used to create (out, but excluding no_generate).
	createsResources []*ResourceDesc
	// Both inputs and output resources (including no_generate).
	usesResources []*ResourceDesc
}

// SyscallAttrs represents call attributes in syzlang.
//
// This structure is the source of truth for the all other parts of the system.
// pkg/compiler uses this structure to parse descriptions.
// syz-sysgen uses this structure to generate code for executor.
//
// Only `bool`s and `uint64`s are currently supported.
//
// See docs/syscall_descriptions_syntax.md for description of individual attributes.
type SyscallAttrs struct {
	Disabled      bool
	Timeout       uint64
	ProgTimeout   uint64
	IgnoreReturn  bool
	BreaksReturns bool
	NoGenerate    bool
	NoMinimize    bool
	RemoteCover   bool
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
	Condition    Expression

	// See Target.initRelatedFields.
	relatedFields map[Type]struct{}
}

func (f *Field) Dir(def Dir) Dir {
	if f.HasDirection {
		return f.Direction
	}
	return def
}

type ArgFinder func(path []string) Arg

// Special case reply of ArgFinder.
var SquashedArgFound = &DataArg{}

type Expression interface {
	fmt.GoStringer
	ForEachValue(func(*Value))
	Clone() Expression
	Evaluate(ArgFinder) (uint64, bool)
}

type BinaryOperator int

const (
	OperatorCompareEq BinaryOperator = iota
	OperatorCompareNeq
	OperatorBinaryAnd
)

type BinaryExpression struct {
	Operator BinaryOperator
	Left     Expression
	Right    Expression
}

func (bo BinaryExpression) GoString() string {
	return fmt.Sprintf("&prog.BinaryExpression{%#v,%#v,%#v}", bo.Operator, bo.Left, bo.Right)
}

func (bo BinaryExpression) ForEachValue(cb func(*Value)) {
	bo.Left.ForEachValue(cb)
	bo.Right.ForEachValue(cb)
}

func (bo *BinaryExpression) Clone() Expression {
	return &BinaryExpression{
		Operator: bo.Operator,
		Left:     bo.Left.Clone(),
		Right:    bo.Right.Clone(),
	}
}

type Value struct {
	// If Path is empty, Value is to be used.
	Value uint64
	// Path to the field.
	Path []string
}

func (v Value) GoString() string {
	return fmt.Sprintf("&prog.Value{%#v,%#v}", v.Value, v.Path)
}

func (v *Value) ForEachValue(cb func(*Value)) {
	cb(v)
}

func (v *Value) Clone() Expression {
	return &Value{v.Value, append([]string{}, v.Path...)}
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

type FlagDesc struct {
	Name   string
	Values []string
}

type ResourceDesc struct {
	Name   string
	Kind   []string
	Values []uint64
	Ctors  []ResourceCtor
}

type ResourceCtor struct {
	Call    *Syscall
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

	// Hint values that don't make sense to use for this type
	// b/c they are expected to be easily guessed by generation/mutation.
	// For example, flags values or combinations of few flags values.
	uselessHints map[uint64]struct{}
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

func (t *IntTypeCommon) uselessHint(v uint64) bool {
	_, ok := t.uselessHints[v]
	return ok
}

func (t *IntTypeCommon) setUselessHints(m map[uint64]struct{}) {
	t.uselessHints = m
}

type uselessHinter interface {
	uselessHint(uint64) bool
	calcUselessHints() []uint64
	setUselessHints(map[uint64]struct{})
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

func (t *ConstType) calcUselessHints() []uint64 {
	return []uint64{t.Val}
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

func (t *IntType) calcUselessHints() []uint64 {
	res := specialInts[:len(specialInts):len(specialInts)]
	align := max(1, t.Align)
	rangeVals := (t.RangeEnd - t.RangeBegin) / align
	if rangeVals != 0 && rangeVals <= 100 {
		for v := t.RangeBegin; v <= t.RangeEnd; v += align {
			res = append(res, v)
		}
	}
	return res
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

func (t *FlagsType) calcUselessHints() []uint64 {
	// Combinations of up to 3 flag values + 0.
	res := []uint64{0}
	vals := t.Vals
	for i0 := 0; i0 < len(vals); i0++ {
		v0 := vals[i0]
		res = append(res, v0)
		if len(vals) <= 10 {
			for i1 := i0 + 1; i1 < len(vals); i1++ {
				v1 := v0 | vals[i1]
				res = append(res, v1)
				if len(vals) <= 7 {
					for i2 := i1 + 1; i2 < len(vals); i2++ {
						v2 := v1 | vals[i2]
						res = append(res, v2)
					}
				}
			}
		}
	}
	return res
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

func (t *LenType) calcUselessHints() []uint64 {
	return nil
}

func (t *LenType) uselessHint(v uint64) bool {
	return v <= maxArrayLen || v > 1<<20
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
	BufferGlob
	BufferCompressed
)

type TextKind int

const (
	TextTarget TextKind = iota
	TextX86Real
	TextX86bit16
	TextX86bit32
	TextX86bit64
	TextArm64
	TextPpc64
)

type BufferType struct {
	TypeCommon
	Kind       BufferKind
	RangeBegin uint64   // for BufferBlobRange kind
	RangeEnd   uint64   // for BufferBlobRange kind
	Text       TextKind // for BufferText
	SubKind    string
	Values     []string // possible values for BufferString and BufferGlob kind
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
	if len(t.Values) == 1 {
		data = []byte(t.Values[0])
	} else if !t.Varlen() {
		data = make([]byte, t.Size())
	}
	return MakeDataArg(t, dir, data)
}

func (t *BufferType) isDefaultArg(arg Arg) bool {
	a := arg.(*DataArg)
	sz := uint64(0)
	if !t.Varlen() {
		sz = t.Size()
	}
	if a.Size() != sz {
		return false
	}
	if a.Dir() == DirOut {
		return true
	}
	if len(t.Values) == 1 {
		return string(a.Data()) == t.Values[0]
	}
	for _, v := range a.Data() {
		if v != 0 {
			return false
		}
	}
	return true
}

func (t *BufferType) IsCompressed() bool {
	return t.Kind == BufferCompressed
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
	Elem           Type
	ElemDir        Dir
	SquashableElem bool
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
	Fields       []Field
	AlignAttr    uint64
	OverlayField int // index of the field marked with out_overlay attribute (0 if no attribute)
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
	idx := t.defaultField()
	f := t.Fields[idx]
	arg := MakeUnionArg(t, dir, f.DefaultArg(f.Dir(dir)), idx)
	arg.transient = t.isConditional()
	return arg
}

func (t *UnionType) defaultField() int {
	// If it's a conditional union, the last field will be the default value.
	if t.isConditional() {
		return len(t.Fields) - 1
	}
	// Otherwise, just take the first.
	return 0
}

func (t *UnionType) isConditional() bool {
	// In pkg/compiler, we ensure that either none of the fields have conditions,
	// or all except the last one.
	return t.Fields[0].Condition != nil
}

func (t *UnionType) isDefaultArg(arg Arg) bool {
	a := arg.(*UnionArg)
	return a.Index == t.defaultField() && isDefault(a.Option)
}

type ConstValue struct {
	Name  string
	Value uint64
}

type TypeCtx struct {
	Meta     *Syscall
	Dir      Dir
	Ptr      *Type
	Optional bool
	Stop     bool // If set by the callback, subtypes of this type are not visited.
}

func ForeachType(syscalls []*Syscall, f func(t Type, ctx *TypeCtx)) {
	for _, meta := range syscalls {
		foreachCallTypeImpl(meta, true, f)
	}
}

func ForeachTypePost(syscalls []*Syscall, f func(t Type, ctx *TypeCtx)) {
	for _, meta := range syscalls {
		foreachCallTypeImpl(meta, false, f)
	}
}

func ForeachCallType(meta *Syscall, f func(t Type, ctx *TypeCtx)) {
	foreachCallTypeImpl(meta, true, f)
}

// We need seen to be keyed by the type, the direction, and the optionality
// bit. Even if the first time we see a type it is optional or DirOut, it
// could be required or DirIn on another path. So to ensure that the
// information we report to the caller is correct, we need to visit both
// occurrences.
type seenKey struct {
	t Type
	d Dir
	o bool
}

func foreachCallTypeImpl(meta *Syscall, preorder bool, f func(t Type, ctx *TypeCtx)) {
	// Note: we specifically don't create seen in ForeachType.
	// It would prune recursion more (across syscalls), but lots of users need to
	// visit each struct per-syscall (e.g. prio, used resources).
	seen := make(map[seenKey]bool)
	for i := range meta.Args {
		foreachTypeRec(f, meta, seen, &meta.Args[i].Type, DirIn, preorder, false)
	}
	if meta.Ret != nil {
		foreachTypeRec(f, meta, seen, &meta.Ret, DirOut, preorder, false)
	}
}

func ForeachArgType(typ Type, f func(t Type, ctx *TypeCtx)) {
	foreachTypeRec(f, nil, make(map[seenKey]bool), &typ, DirIn, true, false)
}

func foreachTypeRec(cb func(t Type, ctx *TypeCtx), meta *Syscall, seen map[seenKey]bool, ptr *Type,
	dir Dir, preorder, optional bool) {
	if _, ref := (*ptr).(Ref); !ref {
		optional = optional || (*ptr).Optional()
	}
	ctx := &TypeCtx{Meta: meta, Dir: dir, Ptr: ptr, Optional: optional}
	if preorder {
		cb(*ptr, ctx)
		if ctx.Stop {
			return
		}
	}
	switch a := (*ptr).(type) {
	case *PtrType:
		foreachTypeRec(cb, meta, seen, &a.Elem, a.ElemDir, preorder, optional)
	case *ArrayType:
		foreachTypeRec(cb, meta, seen, &a.Elem, dir, preorder, optional)
	case *StructType:
		key := seenKey{
			t: a,
			d: dir,
			o: optional,
		}
		if seen[key] {
			break // prune recursion via pointers to structs/unions
		}
		seen[key] = true
		for i, f := range a.Fields {
			foreachTypeRec(cb, meta, seen, &a.Fields[i].Type, f.Dir(dir), preorder, optional)
		}
	case *UnionType:
		key := seenKey{
			t: a,
			d: dir,
			o: optional,
		}
		if seen[key] {
			break // prune recursion via pointers to structs/unions
		}
		seen[key] = true
		for i, f := range a.Fields {
			foreachTypeRec(cb, meta, seen, &a.Fields[i].Type, f.Dir(dir), preorder, optional)
		}
	case *ResourceType, *BufferType, *VmaType, *LenType, *FlagsType,
		*ConstType, *IntType, *ProcType, *CsumType:
	case Ref:
		// This is only needed for pkg/compiler.
	default:
		panic("unknown type")
	}
	if !preorder {
		cb(*ptr, ctx)
		if ctx.Stop {
			panic("Stop is set in post-order iteration")
		}
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
