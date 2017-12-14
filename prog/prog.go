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

// ArgUser is interface of an argument that uses value of another output argument.
type ArgUser interface {
	Uses() *Arg
}

// ArgUsed is interface of an argument that can be used by other arguments.
type ArgUsed interface {
	Used() *map[Arg]bool
}

func isUsed(arg Arg) bool {
	used, ok := arg.(ArgUsed)
	if !ok {
		return false
	}
	return len(*used.Used()) != 0
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

func MakeConstArg(t Type, v uint64) Arg {
	return &ConstArg{ArgCommon: ArgCommon{typ: t}, Val: v}
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

func MakePointerArg(t Type, page uint64, off int, npages uint64, obj Arg) Arg {
	return &PointerArg{
		ArgCommon:  ArgCommon{typ: t},
		PageIndex:  page,
		PageOffset: off,
		PagesNum:   npages,
		Res:        obj,
	}
}

func (arg *PointerArg) Size() uint64 {
	return arg.typ.Size()
}

// Used for BufferType.
type DataArg struct {
	ArgCommon
	data []byte // for in/inout args
	size uint64 // for out Args
}

func MakeDataArg(t Type, data []byte) Arg {
	if t.Dir() == DirOut {
		panic("non-empty output data arg")
	}
	return &DataArg{ArgCommon: ArgCommon{typ: t}, data: append([]byte{}, data...)}
}

func MakeOutDataArg(t Type, size uint64) Arg {
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

func MakeGroupArg(t Type, inner []Arg) Arg {
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

// Used for UnionType.
type UnionArg struct {
	ArgCommon
	Option     Arg
	OptionType Type
}

func MakeUnionArg(t Type, opt Arg, typ Type) Arg {
	return &UnionArg{ArgCommon: ArgCommon{typ: t}, Option: opt, OptionType: typ}
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

func MakeResultArg(t Type, r Arg, v uint64) Arg {
	arg := &ResultArg{ArgCommon: ArgCommon{typ: t}, Res: r, Val: v}
	if r == nil {
		return arg
	}
	used := r.(ArgUsed)
	if *used.Used() == nil {
		*used.Used() = make(map[Arg]bool)
	}
	(*used.Used())[arg] = true
	return arg
}

func (arg *ResultArg) Size() uint64 {
	return arg.typ.Size()
}

func (arg *ResultArg) Used() *map[Arg]bool {
	return &arg.uses
}

func (arg *ResultArg) Uses() *Arg {
	return &arg.Res
}

// Used for ResourceType and VmaType.
// This argument denotes syscall return value.
type ReturnArg struct {
	ArgCommon
	uses map[Arg]bool // ArgResult args that use this arg
}

func MakeReturnArg(t Type) Arg {
	return &ReturnArg{ArgCommon: ArgCommon{typ: t}}
}

func (arg *ReturnArg) Size() uint64 {
	panic("not called")
}

func (arg *ReturnArg) Used() *map[Arg]bool {
	return &arg.uses
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

func defaultArg(t Type) Arg {
	switch typ := t.(type) {
	case *IntType, *ConstType, *FlagsType, *LenType, *ProcType, *CsumType:
		return MakeConstArg(t, t.Default())
	case *ResourceType:
		return MakeResultArg(t, nil, typ.Desc.Type.Default())
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
				elems = append(elems, defaultArg(typ.Type))
			}
		}
		return MakeGroupArg(t, elems)
	case *StructType:
		var inner []Arg
		for _, field := range typ.Fields {
			inner = append(inner, defaultArg(field))
		}
		return MakeGroupArg(t, inner)
	case *UnionType:
		return MakeUnionArg(t, defaultArg(typ.Fields[0]), typ.Fields[0])
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
	if debug {
		p.replaceArgCheck(c, arg, arg1, calls)
	}
	for _, c := range calls {
		p.Target.SanitizeCall(c)
	}
	p.insertBefore(c, calls)
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
	default:
		panic(fmt.Sprintf("replaceArg: bad arg kind %#v", arg))
	}
	p.Target.SanitizeCall(c)
}

func replaceResultArg(arg, arg1 *ResultArg) {
	// Remove link from `a.Res` to `arg`.
	if arg.Res != nil {
		delete(*arg.Res.(ArgUsed).Used(), arg)
	}
	// Copy all fields from `arg1` to `arg` except for the list of args that use `arg`.
	used := *arg.Used()
	*arg = *arg1
	*arg.Used() = used
	// Make the link in `arg.Res` (which is now `Res` of `arg1`) to point to `arg` instead of `arg1`.
	if arg.Res != nil {
		delete(*arg.Res.(ArgUsed).Used(), arg1)
		(*arg.Res.(ArgUsed).Used())[arg] = true
	}
}

// replaceArgCheck checks that c and arg belog to p.
func (p *Prog) replaceArgCheck(c *Call, arg, arg1 Arg, calls []*Call) {
	foundCall, foundArg := false, false
	for _, c0 := range p.Calls {
		if c0 == c {
			if foundCall {
				panic("duplicate call")
			}
			foundCall = true
		}
		for _, newC := range calls {
			if c0 == newC {
				panic("call is already in prog")
			}
		}
		foreachArg(c0, func(arg0, _ Arg, _ *[]Arg) {
			if arg0 == arg {
				if c0 != c {
					panic("wrong call")
				}
				if foundArg {
					panic("duplicate arg")
				}
				foundArg = true
			}
			if arg0 == arg1 {
				panic("arg is already in prog")
			}
		})
	}
	if !foundCall {
		panic("call is not in prog")
	}
	if !foundArg {
		panic("arg is not in prog")
	}
}

// removeArg removes all references to/from arg0 of call c from p.
func (p *Prog) removeArg(c *Call, arg0 Arg) {
	foreachSubarg(arg0, func(arg, _ Arg, _ *[]Arg) {
		if a, ok := arg.(*ResultArg); ok && a.Res != nil {
			if !(*a.Res.(ArgUsed).Used())[arg] {
				panic("broken tree")
			}
			delete(*a.Res.(ArgUsed).Used(), arg)
		}
		if used, ok := arg.(ArgUsed); ok {
			for arg1 := range *used.Used() {
				a1, ok := arg1.(*ResultArg)
				if !ok {
					panic("use references not ArgResult")
				}
				arg2 := MakeResultArg(arg1.Type(), nil, arg1.Type().Default())
				replaceResultArg(a1, arg2.(*ResultArg))
			}
		}
	})
}

// removeCall removes call idx from p.
func (p *Prog) removeCall(idx int) {
	c := p.Calls[idx]
	for _, arg := range c.Args {
		p.removeArg(c, arg)
	}
	p.removeArg(c, c.Ret)
	copy(p.Calls[idx:], p.Calls[idx+1:])
	p.Calls = p.Calls[:len(p.Calls)-1]
}
