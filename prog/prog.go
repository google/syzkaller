// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"reflect"
	"strings"
)

type Prog struct {
	Target      *Target
	Calls       []*Call
	Comments    []string
	EnforceDeps bool

	// Was deserialized using Unsafe mode, so can do unsafe things.
	isUnsafe bool
}

const ExtraCallName = ".extra"

func (p *Prog) ValidateDeps() bool {
	return p.doValidateDeps()
}

func (p *Prog) CallName(call int) string {
	if call >= len(p.Calls) || call < -1 {
		panic(fmt.Sprintf("bad call index %v/%v", call, len(p.Calls)))
	}
	if call == -1 {
		return ExtraCallName
	}
	return p.Calls[call].Meta.Name
}

// OnlyContains determines whether the program only consists of the syscalls from the first argument.
func (p *Prog) OnlyContains(syscalls map[*Syscall]bool) bool {
	for _, c := range p.Calls {
		if !syscalls[c.Meta] {
			return false
		}
	}
	return true
}

// FilterInplace only leaves the allowed system calls and deletes all remaining ones.
func (p *Prog) FilterInplace(allowed map[*Syscall]bool) {
	for i := 0; i < len(p.Calls); {
		c := p.Calls[i]
		if !allowed[c.Meta] {
			p.RemoveCall(i)
			continue
		}
		i++
	}
}

// These properties are parsed and serialized according to the tag and the type
// of the corresponding fields.
// IMPORTANT: keep the exact values of "key" tag for existing props unchanged,
// otherwise the backwards compatibility would be broken.
type CallProps struct {
	FailNth int  `key:"fail_nth"`
	Async   bool `key:"async"`
	Rerun   int  `key:"rerun"`
}

type Call struct {
	Meta    *Syscall
	Args    []Arg
	Ret     *ResultArg
	Props   CallProps
	Comment string
}

func MakeCall(meta *Syscall, args []Arg) *Call {
	return &Call{
		Meta: meta,
		Args: args,
		Ret:  MakeReturnArg(meta.Ret),
	}
}

type Arg interface {
	Type() Type
	Dir() Dir
	Size() uint64

	validate(ctx *validCtx, dir Dir) error
	serialize(ctx *serializer)
}

type ArgCommon struct {
	ref Ref
	dir Dir
}

func (arg *ArgCommon) Type() Type {
	if arg.ref == 0 {
		panic("broken type ref")
	}
	return typeRefs.Load().([]Type)[arg.ref]
}

func (arg *ArgCommon) Dir() Dir {
	return arg.dir
}

// Used for ConstType, IntType, FlagsType, LenType, ProcType and CsumType.
type ConstArg struct {
	ArgCommon
	Val uint64
}

func MakeConstArg(t Type, dir Dir, v uint64) *ConstArg {
	return &ConstArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Val: v}
}

func (arg *ConstArg) Size() uint64 {
	return arg.Type().Size()
}

// Value returns value and pid stride.
func (arg *ConstArg) Value() (uint64, uint64) {
	switch typ := (*arg).Type().(type) {
	case *IntType:
		return arg.Val, 0
	case *ConstType:
		return arg.Val, 0
	case *FlagsType:
		return arg.Val, 0
	case *LenType:
		return arg.Val, 0
	case *ResourceType:
		return arg.Val, 0
	case *CsumType:
		// Checksums are computed dynamically in executor.
		return 0, 0
	case *ProcType:
		if arg.Val == procDefaultValue {
			return 0, 0
		}
		return typ.ValuesStart + arg.Val, typ.ValuesPerProc
	default:
		panic(fmt.Sprintf("unknown ConstArg type %#v", typ))
	}
}

// Used for PtrType and VmaType.
type PointerArg struct {
	ArgCommon
	Address uint64
	VmaSize uint64 // size of the referenced region for vma args
	Res     Arg    // pointee (nil for vma)
}

func MakePointerArg(t Type, dir Dir, addr uint64, data Arg) *PointerArg {
	if data == nil {
		panic("nil pointer data arg")
	}
	return &PointerArg{
		ArgCommon: ArgCommon{ref: t.ref(), dir: DirIn}, // pointers are always in
		Address:   addr,
		Res:       data,
	}
}

func MakeVmaPointerArg(t Type, dir Dir, addr, size uint64) *PointerArg {
	if addr%1024 != 0 {
		panic("unaligned vma address")
	}
	return &PointerArg{
		ArgCommon: ArgCommon{ref: t.ref(), dir: dir},
		Address:   addr,
		VmaSize:   size,
	}
}

func MakeSpecialPointerArg(t Type, dir Dir, index uint64) *PointerArg {
	if index >= maxSpecialPointers {
		panic("bad special pointer index")
	}
	if _, ok := t.(*PtrType); ok {
		dir = DirIn // pointers are always in
	}
	return &PointerArg{
		ArgCommon: ArgCommon{ref: t.ref(), dir: dir},
		Address:   -index,
	}
}

func (arg *PointerArg) Size() uint64 {
	return arg.Type().Size()
}

func (arg *PointerArg) IsSpecial() bool {
	return arg.VmaSize == 0 && arg.Res == nil && -arg.Address < maxSpecialPointers
}

func (target *Target) PhysicalAddr(arg *PointerArg) uint64 {
	if arg.IsSpecial() {
		return target.SpecialPointers[-arg.Address]
	}
	return target.DataOffset + arg.Address
}

// Used for BufferType.
type DataArg struct {
	ArgCommon
	data []byte // for in/inout args
	size uint64 // for out Args
}

func MakeDataArg(t Type, dir Dir, data []byte) *DataArg {
	if dir == DirOut {
		panic("non-empty output data arg")
	}
	return &DataArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, data: append([]byte{}, data...)}
}

func MakeOutDataArg(t Type, dir Dir, size uint64) *DataArg {
	if dir != DirOut {
		panic("empty input data arg")
	}
	return &DataArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, size: size}
}

func (arg *DataArg) Size() uint64 {
	if len(arg.data) != 0 {
		return uint64(len(arg.data))
	}
	return arg.size
}

func (arg *DataArg) Data() []byte {
	if arg.Dir() == DirOut {
		panic("getting data of output data arg")
	}
	return arg.data
}

func (arg *DataArg) SetData(data []byte) {
	if arg.Dir() == DirOut {
		panic("setting data of output data arg")
	}
	arg.data = append([]byte{}, data...)
}

// Used for StructType and ArrayType.
// Logical group of args (struct or array).
type GroupArg struct {
	ArgCommon
	Inner []Arg
}

func MakeGroupArg(t Type, dir Dir, inner []Arg) *GroupArg {
	return &GroupArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Inner: inner}
}

func (arg *GroupArg) Size() uint64 {
	typ0 := arg.Type()
	if !typ0.Varlen() {
		return typ0.Size()
	}
	switch typ := typ0.(type) {
	case *StructType:
		var size, offset uint64
		for i, fld := range arg.Inner {
			if i == typ.OverlayField {
				offset = 0
			}
			offset += fld.Size()
			// Add dynamic alignment at the end and before the overlay part.
			if i+1 == len(arg.Inner) || i+1 == typ.OverlayField {
				if typ.AlignAttr != 0 && offset%typ.AlignAttr != 0 {
					offset += typ.AlignAttr - offset%typ.AlignAttr
				}
			}
			size = max(size, offset)
		}
		return size
	case *ArrayType:
		var size uint64
		for _, elem := range arg.Inner {
			size += elem.Size()
		}
		return size
	default:
		panic(fmt.Sprintf("bad group arg type %v", typ))
	}
}

func (arg *GroupArg) fixedInnerSize() bool {
	switch typ := arg.Type().(type) {
	case *StructType:
		return true
	case *ArrayType:
		return typ.Kind == ArrayRangeLen && typ.RangeBegin == typ.RangeEnd
	default:
		panic(fmt.Sprintf("bad group arg type %v", typ))
	}
}

// Used for UnionType.
type UnionArg struct {
	ArgCommon
	Option Arg
	Index  int // Index of the selected option in the union type.
	// Used for unions with conditional fields.
	// We first create a dummy arg with transient=True and then
	// patch them.
	transient bool
}

func MakeUnionArg(t Type, dir Dir, opt Arg, index int) *UnionArg {
	return &UnionArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Option: opt, Index: index}
}

func (arg *UnionArg) Size() uint64 {
	if !arg.Type().Varlen() {
		return arg.Type().Size()
	}
	return arg.Option.Size()
}

// Used for ResourceType.
// This is the only argument that can be used as syscall return value.
// Either holds constant value or reference another ResultArg.
type ResultArg struct {
	ArgCommon
	Res   *ResultArg          // reference to arg which we use
	OpDiv uint64              // divide result (executed before OpAdd)
	OpAdd uint64              // add to result
	Val   uint64              // value used if Res is nil
	uses  map[*ResultArg]bool // args that use this arg
}

func MakeResultArg(t Type, dir Dir, r *ResultArg, v uint64) *ResultArg {
	arg := &ResultArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Res: r, Val: v}
	if r == nil {
		return arg
	}
	if r.uses == nil {
		r.uses = make(map[*ResultArg]bool)
	}
	r.uses[arg] = true
	return arg
}

func MakeReturnArg(t Type) *ResultArg {
	if t == nil {
		return nil
	}
	return &ResultArg{ArgCommon: ArgCommon{ref: t.ref(), dir: DirOut}}
}

func (arg *ResultArg) Size() uint64 {
	return arg.Type().Size()
}

// Returns inner arg for pointer args.
func InnerArg(arg Arg) Arg {
	if _, ok := arg.Type().(*PtrType); ok {
		res := arg.(*PointerArg).Res
		if res == nil {
			return nil
		}
		return InnerArg(res)
	}
	return arg // Not a pointer.
}

func isDefault(arg Arg) bool {
	return arg.Type().isDefaultArg(arg)
}

func (p *Prog) insertBefore(c *Call, calls []*Call) {
	idx := 0
	for ; idx < len(p.Calls); idx++ {
		if p.Calls[idx] == c {
			break
		}
	}
	var newCalls []*Call
	newCalls = append(newCalls, p.Calls[:idx]...)
	newCalls = append(newCalls, calls...)
	if idx < len(p.Calls) {
		newCalls = append(newCalls, p.Calls[idx])
		newCalls = append(newCalls, p.Calls[idx+1:]...)
	}
	p.Calls = newCalls
}

// replaceArg replaces arg with arg1 in a program.
func replaceArg(arg, arg1 Arg) {
	if arg == arg1 {
		panic("replacing an argument with itself")
	}
	switch a := arg.(type) {
	case *ConstArg:
		*a = *arg1.(*ConstArg)
	case *ResultArg:
		replaceResultArg(a, arg1.(*ResultArg))
	case *PointerArg:
		*a = *arg1.(*PointerArg)
	case *UnionArg:
		if a.Option != nil {
			removeArg(a.Option)
		}
		*a = *arg1.(*UnionArg)
	case *DataArg:
		*a = *arg1.(*DataArg)
	case *GroupArg:
		_, isStruct := arg.Type().(*StructType)
		a1 := arg1.(*GroupArg)
		if isStruct && len(a.Inner) != len(a1.Inner) {
			panic(fmt.Sprintf("replaceArg: group fields don't match: %v/%v",
				len(a.Inner), len(a1.Inner)))
		}
		a.ArgCommon = a1.ArgCommon
		// Replace min(|a|, |a1|) arguments.
		for i := 0; i < len(a.Inner) && i < len(a1.Inner); i++ {
			replaceArg(a.Inner[i], a1.Inner[i])
		}
		// Remove extra arguments of a.
		for len(a.Inner) > len(a1.Inner) {
			i := len(a.Inner) - 1
			removeArg(a.Inner[i])
			a.Inner[i] = nil
			a.Inner = a.Inner[:i]
		}
		// Add extra arguments to a.
		for i := len(a.Inner); i < len(a1.Inner); i++ {
			a.Inner = append(a.Inner, a1.Inner[i])
		}
		if debug && len(a.Inner) != len(a1.Inner) {
			panic("replaceArg implementation bug")
		}
	default:
		panic(fmt.Sprintf("replaceArg: bad arg kind %#v", arg))
	}
}

func replaceResultArg(arg, arg1 *ResultArg) {
	// Remove link from `a.Res` to `arg`.
	if arg.Res != nil {
		delete(arg.Res.uses, arg)
	}
	// Copy all fields from `arg1` to `arg` except for the list of args that use `arg`.
	uses := arg.uses
	*arg = *arg1
	arg.uses = uses
	// Make the link in `arg.Res` (which is now `Res` of `arg1`) to point to `arg` instead of `arg1`.
	if arg.Res != nil {
		resUses := arg.Res.uses
		delete(resUses, arg1)
		resUses[arg] = true
	}
}

// removeArg removes all references to/from arg0 from a program.
func removeArg(arg0 Arg) {
	ForeachSubArg(arg0, func(arg Arg, ctx *ArgCtx) {
		a, ok := arg.(*ResultArg)
		if !ok {
			return
		}
		if a.Res != nil {
			uses := a.Res.uses
			if !uses[a] {
				panic("broken tree")
			}
			delete(uses, a)
		}
		for arg1 := range a.uses {
			arg2 := arg1.Type().DefaultArg(arg1.Dir()).(*ResultArg)
			replaceResultArg(arg1, arg2)
		}
	})
}

// RemoveCall removes call idx from p.
func (p *Prog) RemoveCall(idx int) {
	c := p.Calls[idx]
	for _, arg := range c.Args {
		removeArg(arg)
	}
	if c.Ret != nil {
		removeArg(c.Ret)
	}
	copy(p.Calls[idx:], p.Calls[idx+1:])
	p.Calls = p.Calls[:len(p.Calls)-1]
}

func (p *Prog) sanitizeFix() {
	if err := p.sanitize(true); err != nil {
		panic(err)
	}
}

// FormatArg returns a string slice representation of an argument with one
// entry per line in the output. The formatting roughly corresponds to syzlang
// descriptions and is intended to be human readable.
func FormatArg(arg Arg, name string) []string {
	const indent string = "  " // Two spaces.
	makeIndent := func(level int) string {
		return strings.Repeat(indent, level)
	}

	// Depth-first search starting at initial argument, incrementing the indent
	// level as we go deeper.
	var visit func(Arg, string, int) []string
	visit = func(arg Arg, name string, depth int) []string {
		var lines []string

		var lineBuilder strings.Builder
		lineBuilder.WriteString(makeIndent(depth))

		if name != "" {
			fmt.Fprintf(&lineBuilder, "%s: ", name)
		}

		switch a := arg.(type) {
		case *GroupArg:
			fmt.Fprintf(&lineBuilder, "%s {", a.Type().String())
			lines = append(lines, lineBuilder.String())

			s, isStruct := a.ArgCommon.Type().(*StructType)
			for i, inner := range a.Inner {
				// For GroupArgs, only those of type StructType have named
				// children.
				childName := ""
				if isStruct {
					childName = s.Fields[i].Name
				}
				lines = append(lines, visit(inner, childName, depth+1)...)
			}
			lines = append(lines, makeIndent(depth)+"}")
		case *ConstArg:
			fmt.Fprintf(&lineBuilder, "%s = 0x%x (%d bytes)", a.Type().Name(), a.Val, a.Size())
			lines = append(lines, lineBuilder.String())
		case *DataArg:
			tpe, ok := a.Type().(*BufferType)
			if !ok {
				panic("data args should be a buffer type")
			}

			fmt.Fprintf(&lineBuilder, "%s: ", a.Type().String())

			// Result buffer - nothing to display.
			if a.Dir() == DirOut {
				fmt.Fprint(&lineBuilder, "(DirOut)")
			} else {
				// Compressed buffers (e.g., fs images) tend to be very large
				// and it doesn't make much sense to output their contents.
				if tpe.Kind == BufferCompressed {
					fmt.Fprintf(&lineBuilder, "(compressed buffer with length 0x%x)", len(a.Data()))
				} else {
					fmt.Fprintf(&lineBuilder, "{% x} (length 0x%x)", a.Data(), len(a.Data()))
				}
			}
			lines = append(lines, lineBuilder.String())
		case *PointerArg:
			if a.Res != nil {
				fmt.Fprintf(&lineBuilder, "%s {", a.Type().String())
				lines = append(lines, lineBuilder.String())
				lines = append(lines, visit(a.Res, "", depth+1)...)
				lines = append(lines, makeIndent(depth)+"}")
			} else {
				if a.VmaSize == 0 {
					lineBuilder.WriteString("nil")
				} else {
					fmt.Fprintf(&lineBuilder, "VMA[0x%x]", a.VmaSize)
				}
				lines = append(lines, lineBuilder.String())
			}
		case *UnionArg:
			union, ok := a.ArgCommon.Type().(*UnionType)
			if !ok {
				panic("a UnionArg should have an ArgCommon of type UnionType")
			}
			fmt.Fprintf(&lineBuilder, "union %s {", a.Type().Name())
			lines = append(lines, lineBuilder.String())
			if a.Option != nil {
				lines = append(lines, visit(a.Option, union.Fields[a.Index].Name, depth+1)...)
			}
			lines = append(lines, makeIndent(depth)+"}")
		case *ResultArg:
			fmt.Fprintf(&lineBuilder, "%s (resource)", a.ArgCommon.Type().String())
			lines = append(lines, lineBuilder.String())
		default:
			// We shouldn't hit this because the switch statements cover every
			// prog.Arg implementation.
			panic("Unsupported argument type.")
		}
		return lines
	}

	return visit(arg, name, 0)
}

func (p *Prog) sanitize(fix bool) error {
	for _, c := range p.Calls {
		if err := p.Target.sanitize(c, fix); err != nil {
			return err
		}
	}
	return nil
}

// TODO: This method might be more generic - it can be applied to any struct.
func (props *CallProps) ForeachProp(f func(fieldName, key string, value reflect.Value)) {
	valueObj := reflect.ValueOf(props).Elem()
	typeObj := valueObj.Type()
	for i := 0; i < valueObj.NumField(); i++ {
		fieldValue := valueObj.Field(i)
		fieldType := typeObj.Field(i)
		f(fieldType.Name, fieldType.Tag.Get("key"), fieldValue)
	}
}
