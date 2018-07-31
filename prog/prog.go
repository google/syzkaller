// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

type Prog struct {
	Target *Target
	Calls  []*Call
}

type Call struct {
	Meta    *Syscall
	Args    []Arg
	Ret     *ResultArg
	Comment string
}

type Arg interface {
	Type() Type
	Size() uint64

	validate(ctx *validCtx) error
	serialize(ctx *serializer)
}

type ArgCommon struct {
	typ Type
}

func (arg *ArgCommon) Type() Type {
	return arg.typ
}

// Used for ConstType, IntType, FlagsType, LenType, ProcType and CsumType.
type ConstArg struct {
	ArgCommon
	Val uint64
}

func MakeConstArg(t Type, v uint64) *ConstArg {
	return &ConstArg{ArgCommon: ArgCommon{typ: t}, Val: v}
}

func (arg *ConstArg) Size() uint64 {
	return arg.typ.Size()
}

// Value returns value, pid stride and endianness.
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
	case *CsumType:
		// Checksums are computed dynamically in executor.
		return 0, 0
	case *ResourceType:
		return arg.Val, 0
	case *ProcType:
		if arg.Val == typ.Default() {
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

func MakePointerArg(t Type, addr uint64, data Arg) *PointerArg {
	if data == nil {
		panic("nil pointer data arg")
	}
	return &PointerArg{
		ArgCommon: ArgCommon{typ: t},
		Address:   addr,
		Res:       data,
	}
}

func MakeVmaPointerArg(t Type, addr, size uint64) *PointerArg {
	if addr%1024 != 0 {
		panic("unaligned vma address")
	}
	return &PointerArg{
		ArgCommon: ArgCommon{typ: t},
		Address:   addr,
		VmaSize:   size,
	}
}

func MakeNullPointerArg(t Type) *PointerArg {
	return &PointerArg{
		ArgCommon: ArgCommon{typ: t},
	}
}

func (arg *PointerArg) Size() uint64 {
	return arg.typ.Size()
}

func (arg *PointerArg) IsNull() bool {
	return arg.Address == 0 && arg.VmaSize == 0 && arg.Res == nil
}

// Used for BufferType.
type DataArg struct {
	ArgCommon
	data []byte // for in/inout args
	size uint64 // for out Args
}

func MakeDataArg(t Type, data []byte) *DataArg {
	if t.Dir() == DirOut {
		panic("non-empty output data arg")
	}
	return &DataArg{ArgCommon: ArgCommon{typ: t}, data: append([]byte{}, data...)}
}

func MakeOutDataArg(t Type, size uint64) *DataArg {
	if t.Dir() != DirOut {
		panic("empty input data arg")
	}
	return &DataArg{ArgCommon: ArgCommon{typ: t}, size: size}
}

func (arg *DataArg) Size() uint64 {
	if len(arg.data) != 0 {
		return uint64(len(arg.data))
	}
	return arg.size
}

func (arg *DataArg) Data() []byte {
	if arg.Type().Dir() == DirOut {
		panic("getting data of output data arg")
	}
	return arg.data
}

// Used for StructType and ArrayType.
// Logical group of args (struct or array).
type GroupArg struct {
	ArgCommon
	Inner []Arg
}

func MakeGroupArg(t Type, inner []Arg) *GroupArg {
	return &GroupArg{ArgCommon: ArgCommon{typ: t}, Inner: inner}
}

func (arg *GroupArg) Size() uint64 {
	typ0 := arg.Type()
	if !typ0.Varlen() {
		return typ0.Size()
	}
	switch typ := typ0.(type) {
	case *StructType:
		var size uint64
		for _, fld := range arg.Inner {
			if !fld.Type().BitfieldMiddle() {
				size += fld.Size()
			}
		}
		if typ.AlignAttr != 0 && size%typ.AlignAttr != 0 {
			size += typ.AlignAttr - size%typ.AlignAttr
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
}

func MakeUnionArg(t Type, opt Arg) *UnionArg {
	return &UnionArg{ArgCommon: ArgCommon{typ: t}, Option: opt}
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
	uses  map[*ResultArg]bool // ArgResult args that use this arg
}

func MakeResultArg(t Type, r *ResultArg, v uint64) *ResultArg {
	arg := &ResultArg{ArgCommon: ArgCommon{typ: t}, Res: r, Val: v}
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
	if t.Dir() != DirOut {
		panic("return arg is not out")
	}
	return &ResultArg{ArgCommon: ArgCommon{typ: t}}
}

func (arg *ResultArg) Size() uint64 {
	return arg.typ.Size()
}

// Returns inner arg for pointer args.
func InnerArg(arg Arg) Arg {
	if t, ok := arg.Type().(*PtrType); ok {
		if a, ok := arg.(*PointerArg); ok {
			if a.Res == nil {
				if !t.Optional() {
					panic(fmt.Sprintf("non-optional pointer is nil\narg: %+v\ntype: %+v", a, t))
				}
				return nil
			}
			return InnerArg(a.Res)
		}
		return nil // *ConstArg.
	}
	return arg // Not a pointer.
}

func (target *Target) defaultArg(t Type) Arg {
	switch typ := t.(type) {
	case *IntType, *ConstType, *FlagsType, *LenType, *ProcType, *CsumType:
		return MakeConstArg(t, t.Default())
	case *ResourceType:
		return MakeResultArg(t, nil, typ.Default())
	case *BufferType:
		if t.Dir() == DirOut {
			var sz uint64
			if !typ.Varlen() {
				sz = typ.Size()
			}
			return MakeOutDataArg(t, sz)
		}
		var data []byte
		if !typ.Varlen() {
			data = make([]byte, typ.Size())
		}
		return MakeDataArg(t, data)
	case *ArrayType:
		var elems []Arg
		if typ.Kind == ArrayRangeLen && typ.RangeBegin == typ.RangeEnd {
			for i := uint64(0); i < typ.RangeBegin; i++ {
				elems = append(elems, target.defaultArg(typ.Type))
			}
		}
		return MakeGroupArg(t, elems)
	case *StructType:
		var inner []Arg
		for _, field := range typ.Fields {
			inner = append(inner, target.defaultArg(field))
		}
		return MakeGroupArg(t, inner)
	case *UnionType:
		return MakeUnionArg(t, target.defaultArg(typ.Fields[0]))
	case *VmaType:
		if t.Optional() {
			return MakeNullPointerArg(t)
		}
		return MakeVmaPointerArg(t, 0, target.PageSize)
	case *PtrType:
		if t.Optional() {
			return MakeNullPointerArg(t)
		}
		return MakePointerArg(t, 0, target.defaultArg(typ.Type))
	default:
		panic(fmt.Sprintf("unknown arg type: %#v", t))
	}
}

func (target *Target) isDefaultArg(arg Arg) bool {
	if IsPad(arg.Type()) {
		return true
	}
	switch a := arg.(type) {
	case *ConstArg:
		switch t := a.Type().(type) {
		case *IntType, *ConstType, *FlagsType, *LenType, *ProcType, *CsumType:
			return a.Val == t.Default()
		default:
			panic(fmt.Sprintf("unknown const type: %#v", t))
		}
	case *GroupArg:
		if !a.fixedInnerSize() && len(a.Inner) != 0 {
			return false
		}
		for _, elem := range a.Inner {
			if !target.isDefaultArg(elem) {
				return false
			}
		}
		return true
	case *UnionArg:
		t := a.Type().(*UnionType)
		return a.Option.Type().FieldName() == t.Fields[0].FieldName() &&
			target.isDefaultArg(a.Option)
	case *DataArg:
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
	case *PointerArg:
		switch t := a.Type().(type) {
		case *PtrType:
			if t.Optional() {
				return a.IsNull()
			}
			return a.Address == 0 && target.isDefaultArg(a.Res)
		case *VmaType:
			if t.Optional() {
				return a.IsNull()
			}
			return a.Address == 0 && a.VmaSize == target.PageSize
		default:
			panic(fmt.Sprintf("unknown pointer type: %#v", t))
		}
	case *ResultArg:
		t := a.Type().(*ResourceType)
		return a.Res == nil && a.OpDiv == 0 && a.OpAdd == 0 &&
			len(a.uses) == 0 && a.Val == t.Default()
	}
	return false
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
	switch a := arg.(type) {
	case *ConstArg:
		*a = *arg1.(*ConstArg)
	case *ResultArg:
		replaceResultArg(a, arg1.(*ResultArg))
	case *PointerArg:
		*a = *arg1.(*PointerArg)
	case *UnionArg:
		*a = *arg1.(*UnionArg)
	case *DataArg:
		*a = *arg1.(*DataArg)
	case *GroupArg:
		a1 := arg1.(*GroupArg)
		if len(a.Inner) != len(a1.Inner) {
			panic(fmt.Sprintf("replaceArg: group fields don't match: %v/%v",
				len(a.Inner), len(a1.Inner)))
		}
		a.ArgCommon = a1.ArgCommon
		for i := range a.Inner {
			replaceArg(a.Inner[i], a1.Inner[i])
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
		if a, ok := arg.(*ResultArg); ok {
			if a.Res != nil {
				uses := a.Res.uses
				if !uses[a] {
					panic("broken tree")
				}
				delete(uses, a)
			}
			for arg1 := range a.uses {
				arg2 := MakeResultArg(arg1.Type(), nil, arg1.Type().Default())
				replaceResultArg(arg1, arg2)
			}
		}
	})
}

// removeCall removes call idx from p.
func (p *Prog) removeCall(idx int) {
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
