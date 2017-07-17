// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"

	"github.com/google/syzkaller/sys"
)

type Prog struct {
	Calls []*Call
}

type Call struct {
	Meta *sys.Call
	Args []Arg
	Ret  Arg
}

type Arg interface {
	Type() sys.Type
	Size() uintptr
}

type ArgCommon struct {
	typ sys.Type
}

func (arg *ArgCommon) Type() sys.Type {
	return arg.typ
}

// Used for ConstType, IntType, FlagsType, LenType, ProcType and CsumType.
type ConstArg struct {
	ArgCommon
	Val uintptr
}

func (arg *ConstArg) Size() uintptr {
	return arg.typ.Size()
}

// Returns value taking endianness and executor pid into consideration.
func (arg *ConstArg) Value(pid int) uintptr {
	switch typ := (*arg).Type().(type) {
	case *sys.IntType:
		return encodeValue(arg.Val, typ.Size(), typ.BigEndian)
	case *sys.ConstType:
		return encodeValue(arg.Val, typ.Size(), typ.BigEndian)
	case *sys.FlagsType:
		return encodeValue(arg.Val, typ.Size(), typ.BigEndian)
	case *sys.LenType:
		return encodeValue(arg.Val, typ.Size(), typ.BigEndian)
	case *sys.CsumType:
		// Checksums are computed dynamically in executor.
		return 0
	case *sys.ResourceType:
		if t, ok := typ.Desc.Type.(*sys.IntType); ok {
			return encodeValue(arg.Val, t.Size(), t.BigEndian)
		} else {
			panic(fmt.Sprintf("bad base type for a resource: %v", t))
		}
	case *sys.ProcType:
		val := uintptr(typ.ValuesStart) + uintptr(typ.ValuesPerProc)*uintptr(pid) + arg.Val
		return encodeValue(val, typ.Size(), typ.BigEndian)
	}
	return arg.Val
}

// Used for PtrType and VmaType.
// Even if these are always constant (for reproducibility), we use a separate
// type because they are represented in an abstract (base+page+offset) form.
type PointerArg struct {
	ArgCommon
	PageIndex  uintptr
	PageOffset int     // offset within a page
	PagesNum   uintptr // number of available pages
	Res        Arg     // pointee
}

func (arg *PointerArg) Size() uintptr {
	return arg.typ.Size()
}

// Used for BufferType.
type DataArg struct {
	ArgCommon
	Data []byte
}

func (arg *DataArg) Size() uintptr {
	return uintptr(len(arg.Data))
}

// Used for StructType and ArrayType.
// Logical group of args (struct or array).
type GroupArg struct {
	ArgCommon
	Inner []Arg
}

func (arg *GroupArg) Size() uintptr {
	switch typ := (*arg).Type().(type) {
	case *sys.StructType:
		var size uintptr
		for _, fld := range arg.Inner {
			if fld.Type().BitfieldLength() == 0 || fld.Type().BitfieldLast() {
				size += fld.Size()
			}
		}
		align := typ.Align()
		if size%align != 0 {
			if typ.Varlen() {
				size += align - size%align
			} else {
				panic(fmt.Sprintf("struct %+v with type %+v has static size %v, which isn't aligned to %v", arg, typ, size, align))
			}
		}
		return size
	case *sys.ArrayType:
		var size uintptr
		for _, in := range arg.Inner {
			size += in.Size()
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
	OptionType sys.Type
}

func (arg *UnionArg) Size() uintptr {
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
	OpDiv uintptr      // divide result (executed before OpAdd)
	OpAdd uintptr      // add to result
	Val   uintptr      // value used if Res is nil
	uses  map[Arg]bool // ArgResult args that use this arg
}

func (arg *ResultArg) Size() uintptr {
	return arg.typ.Size()
}

// Used for ResourceType and VmaType.
// This argument denotes syscall return value.
type ReturnArg struct {
	ArgCommon
	uses map[Arg]bool // ArgResult args that use this arg
}

func (arg *ReturnArg) Size() uintptr {
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
	if t, ok := arg.Type().(*sys.PtrType); ok {
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

func encodeValue(value, size uintptr, bigEndian bool) uintptr {
	if !bigEndian {
		return value
	}
	switch size {
	case 2:
		return uintptr(swap16(uint16(value)))
	case 4:
		return uintptr(swap32(uint32(value)))
	case 8:
		return uintptr(swap64(uint64(value)))
	default:
		panic(fmt.Sprintf("bad size %v for value %v", size, value))
	}
}

func constArg(t sys.Type, v uintptr) Arg {
	return &ConstArg{ArgCommon: ArgCommon{typ: t}, Val: v}
}

func resultArg(t sys.Type, r Arg, v uintptr) Arg {
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

func dataArg(t sys.Type, data []byte) Arg {
	return &DataArg{ArgCommon: ArgCommon{typ: t}, Data: append([]byte{}, data...)}
}

func pointerArg(t sys.Type, page uintptr, off int, npages uintptr, obj Arg) Arg {
	return &PointerArg{ArgCommon: ArgCommon{typ: t}, PageIndex: page, PageOffset: off, PagesNum: npages, Res: obj}
}

func groupArg(t sys.Type, inner []Arg) Arg {
	return &GroupArg{ArgCommon: ArgCommon{typ: t}, Inner: inner}
}

func unionArg(t sys.Type, opt Arg, typ sys.Type) Arg {
	return &UnionArg{ArgCommon: ArgCommon{typ: t}, Option: opt, OptionType: typ}
}

func returnArg(t sys.Type) Arg {
	return &ReturnArg{ArgCommon: ArgCommon{typ: t}}
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
		sanitizeCall(c)
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
	sanitizeCall(c)
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
				arg2 := resultArg(arg1.Type(), nil, arg1.Type().Default())
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
