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
	Meta *Syscall
	Args []Arg
	Ret  Arg
}

type Arg interface {
	Type() Type
	Size() uint64
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

func (arg *ConstArg) Size() uint64 {
	return arg.typ.Size()
}

// Returns value taking endianness and executor pid into consideration.
func (arg *ConstArg) Value(pid int) uint64 {
	switch typ := (*arg).Type().(type) {
	case *IntType:
		return encodeValue(arg.Val, typ.Size(), typ.BigEndian)
	case *ConstType:
		return encodeValue(arg.Val, typ.Size(), typ.BigEndian)
	case *FlagsType:
		return encodeValue(arg.Val, typ.Size(), typ.BigEndian)
	case *LenType:
		return encodeValue(arg.Val, typ.Size(), typ.BigEndian)
	case *CsumType:
		// Checksums are computed dynamically in executor.
		return 0
	case *ResourceType:
		if t, ok := typ.Desc.Type.(*IntType); ok {
			return encodeValue(arg.Val, t.Size(), t.BigEndian)
		} else {
			panic(fmt.Sprintf("bad base type for a resource: %v", t))
		}
	case *ProcType:
		val := typ.ValuesStart + typ.ValuesPerProc*uint64(pid) + arg.Val
		return encodeValue(val, typ.Size(), typ.BigEndian)
	}
	return arg.Val
}

// Used for PtrType and VmaType.
// Even if these are always constant (for reproducibility), we use a separate
// type because they are represented in an abstract (base+page+offset) form.
type PointerArg struct {
	ArgCommon
	PageIndex  uint64
	PageOffset int    // offset within a page
	PagesNum   uint64 // number of available pages
	Res        Arg    // pointee
}

func (arg *PointerArg) Size() uint64 {
	return arg.typ.Size()
}

// Used for BufferType.
type DataArg struct {
	ArgCommon
	Data []byte
}

func (arg *DataArg) Size() uint64 {
	return uint64(len(arg.Data))
}

// Used for StructType and ArrayType.
// Logical group of args (struct or array).
type GroupArg struct {
	ArgCommon
	Inner []Arg
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

// Used for UnionType.
type UnionArg struct {
	ArgCommon
	Option     Arg
	OptionType Type
}

func (arg *UnionArg) Size() uint64 {
	if !arg.Type().Varlen() {
		return arg.Type().Size()
	} else {
		return arg.Option.Size()
	}
}

// Used for ResourceType.
// Either holds constant value or reference another ResultArg or ReturnArg.
type ResultArg struct {
	ArgCommon
	Res   Arg          // reference to arg which we use
	OpDiv uint64       // divide result (executed before OpAdd)
	OpAdd uint64       // add to result
	Val   uint64       // value used if Res is nil
	uses  map[Arg]bool // ArgResult args that use this arg
}

func (arg *ResultArg) Size() uint64 {
	return arg.typ.Size()
}

// Used for ResourceType and VmaType.
// This argument denotes syscall return value.
type ReturnArg struct {
	ArgCommon
	uses map[Arg]bool // ArgResult args that use this arg
}

func (arg *ReturnArg) Size() uint64 {
	panic("not called")
}

type ArgUsed interface {
	Used() *map[Arg]bool
}

func (arg *ResultArg) Used() *map[Arg]bool {
	return &arg.uses
}

func (arg *ReturnArg) Used() *map[Arg]bool {
	return &arg.uses
}

type ArgUser interface {
	Uses() *Arg
}

func (arg *ResultArg) Uses() *Arg {
	return &arg.Res
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
			} else {
				return InnerArg(a.Res)
			}
		}
		return nil // *ConstArg.
	}
	return arg // Not a pointer.
}

func encodeValue(value uint64, size uint64, bigEndian bool) uint64 {
	if !bigEndian {
		return value
	}
	switch size {
	case 2:
		return uint64(swap16(uint16(value)))
	case 4:
		return uint64(swap32(uint32(value)))
	case 8:
		return swap64(value)
	default:
		panic(fmt.Sprintf("bad size %v for value %v", size, value))
	}
}

func MakeConstArg(t Type, v uint64) Arg {
	return &ConstArg{ArgCommon: ArgCommon{typ: t}, Val: v}
}

func MakeResultArg(t Type, r Arg, v uint64) Arg {
	arg := &ResultArg{ArgCommon: ArgCommon{typ: t}, Res: r, Val: v}
	if r == nil {
		return arg
	}
	if used, ok := r.(ArgUsed); ok {
		if *used.Used() == nil {
			*used.Used() = make(map[Arg]bool)
		}
		if (*used.Used())[arg] {
			panic("already used")
		}
		(*used.Used())[arg] = true
	}
	return arg
}

func dataArg(t Type, data []byte) Arg {
	return &DataArg{ArgCommon: ArgCommon{typ: t}, Data: append([]byte{}, data...)}
}

func MakePointerArg(t Type, page uint64, off int, npages uint64, obj Arg) Arg {
	return &PointerArg{ArgCommon: ArgCommon{typ: t}, PageIndex: page, PageOffset: off, PagesNum: npages, Res: obj}
}

func MakeGroupArg(t Type, inner []Arg) Arg {
	return &GroupArg{ArgCommon: ArgCommon{typ: t}, Inner: inner}
}

func unionArg(t Type, opt Arg, typ Type) Arg {
	return &UnionArg{ArgCommon: ArgCommon{typ: t}, Option: opt, OptionType: typ}
}

func MakeReturnArg(t Type) Arg {
	return &ReturnArg{ArgCommon: ArgCommon{typ: t}}
}

func defaultArg(t Type) Arg {
	switch typ := t.(type) {
	case *IntType, *ConstType, *FlagsType, *LenType, *ProcType, *CsumType:
		return MakeConstArg(t, t.Default())
	case *ResourceType:
		return MakeResultArg(t, nil, typ.Desc.Type.Default())
	case *BufferType:
		var data []byte
		if typ.Kind == BufferString && typ.TypeSize != 0 {
			data = make([]byte, typ.TypeSize)
		}
		return dataArg(t, data)
	case *ArrayType:
		return MakeGroupArg(t, nil)
	case *StructType:
		var inner []Arg
		for _, field := range typ.Fields {
			inner = append(inner, defaultArg(field))
		}
		return MakeGroupArg(t, inner)
	case *UnionType:
		return unionArg(t, defaultArg(typ.Fields[0]), typ.Fields[0])
	case *VmaType:
		return MakePointerArg(t, 0, 0, 1, nil)
	case *PtrType:
		var res Arg
		if !t.Optional() && t.Dir() != DirOut {
			res = defaultArg(typ.Type)
		}
		return MakePointerArg(t, 0, 0, 0, res)
	default:
		panic("unknown arg type")
	}
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

// replaceArg replaces arg with arg1 in call c in program p, and inserts calls before arg call.
func (p *Prog) replaceArg(c *Call, arg, arg1 Arg, calls []*Call) {
	for _, c := range calls {
		p.Target.SanitizeCall(c)
	}
	p.insertBefore(c, calls)
	switch a := arg.(type) {
	case *ConstArg:
		*a = *arg1.(*ConstArg)
	case *ResultArg:
		// Remove link from `a.Res` to `arg`.
		if a.Res != nil {
			delete(*a.Res.(ArgUsed).Used(), arg)
		}
		// Copy all fields from `arg1` to `arg` except for the list of args that use `arg`.
		used := *arg.(ArgUsed).Used()
		*a = *arg1.(*ResultArg)
		*arg.(ArgUsed).Used() = used
		// Make the link in `a.Res` (which is now `Res` of `arg1`) to point to `arg` instead of `arg1`.
		if a.Res != nil {
			delete(*a.Res.(ArgUsed).Used(), arg1)
			(*a.Res.(ArgUsed).Used())[arg] = true
		}
	case *PointerArg:
		*a = *arg1.(*PointerArg)
	case *UnionArg:
		*a = *arg1.(*UnionArg)
	default:
		panic(fmt.Sprintf("replaceArg: bad arg kind %v", arg))
	}
	p.Target.SanitizeCall(c)
}

// removeArg removes all references to/from arg0 of call c from p.
func (p *Prog) removeArg(c *Call, arg0 Arg) {
	foreachSubarg(arg0, func(arg, _ Arg, _ *[]Arg) {
		if a, ok := arg.(*ResultArg); ok && a.Res != nil {
			if _, ok := (*a.Res.(ArgUsed).Used())[arg]; !ok {
				panic("broken tree")
			}
			delete(*a.Res.(ArgUsed).Used(), arg)
		}
		if used, ok := arg.(ArgUsed); ok {
			for arg1 := range *used.Used() {
				if _, ok := arg1.(*ResultArg); !ok {
					panic("use references not ArgResult")
				}
				arg2 := MakeResultArg(arg1.Type(), nil, arg1.Type().Default())
				p.replaceArg(c, arg1, arg2, nil)
			}
		}
	})
}

// removeCall removes call idx from p.
func (p *Prog) removeCall(idx int) {
	c := p.Calls[idx]
	copy(p.Calls[idx:], p.Calls[idx+1:])
	p.Calls = p.Calls[:len(p.Calls)-1]
	for _, arg := range c.Args {
		p.removeArg(c, arg)
	}
	p.removeArg(c, c.Ret)
}
