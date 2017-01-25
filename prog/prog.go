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
	Args []*Arg
	Ret  *Arg
}

type Arg struct {
	Type         sys.Type
	Kind         ArgKind
	Val          uintptr       // value of ArgConst
	AddrPage     uintptr       // page index for ArgPointer address, page count for ArgPageSize
	AddrOffset   int           // page offset for ArgPointer address
	AddrPagesNum uintptr       // number of available pages for ArgPointer
	Data         []byte        // data of ArgData
	Inner        []*Arg        // subargs of ArgGroup
	Res          *Arg          // target of ArgResult, pointee for ArgPointer
	Uses         map[*Arg]bool // this arg is used by those ArgResult args
	OpDiv        uintptr       // divide result for ArgResult (executed before OpAdd)
	OpAdd        uintptr       // add to result for ArgResult

	// ArgUnion/UnionType
	Option     *Arg
	OptionType sys.Type
}

type ArgKind int

const (
	ArgConst ArgKind = iota
	ArgResult
	ArgPointer  // even if these are always constant (for reproducibility), we use a separate type because they are represented in an abstract (base+page+offset) form
	ArgPageSize // same as ArgPointer but base is not added, so it represents "lengths" in pages
	ArgData
	ArgGroup // logical group of args (struct or array)
	ArgUnion
	ArgReturn // fake value denoting syscall return value
)

// Returns inner arg for PtrType args
func (a *Arg) InnerArg() *Arg {
	switch typ := a.Type.(type) {
	case *sys.PtrType:
		if a.Res == nil {
			if !typ.Optional() {
				panic(fmt.Sprintf("non-optional pointer is nil\narg: %+v\ntype: %+v", a, typ))
			}
			return nil
		} else {
			return a.Res.InnerArg()
		}
	default:
		return a
	}
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

// Returns value taking endianness into consideration.
func (a *Arg) Value(pid int) uintptr {
	switch typ := a.Type.(type) {
	case *sys.IntType:
		return encodeValue(a.Val, typ.Size(), typ.BigEndian)
	case *sys.ConstType:
		return encodeValue(a.Val, typ.Size(), typ.BigEndian)
	case *sys.FlagsType:
		return encodeValue(a.Val, typ.Size(), typ.BigEndian)
	case *sys.LenType:
		return encodeValue(a.Val, typ.Size(), typ.BigEndian)
	case *sys.CsumType:
		return encodeValue(a.Val, typ.Size(), typ.BigEndian)
	case *sys.ProcType:
		val := uintptr(typ.ValuesStart) + uintptr(typ.ValuesPerProc)*uintptr(pid) + a.Val
		return encodeValue(val, typ.Size(), typ.BigEndian)
	}
	return a.Val
}

func (a *Arg) Size() uintptr {
	switch typ := a.Type.(type) {
	case *sys.IntType, *sys.LenType, *sys.FlagsType, *sys.ConstType,
		*sys.ResourceType, *sys.VmaType, *sys.PtrType, *sys.ProcType, *sys.CsumType:
		return typ.Size()
	case *sys.BufferType:
		return uintptr(len(a.Data))
	case *sys.StructType:
		var size uintptr
		for _, fld := range a.Inner {
			if fld.Type.BitfieldLength() == 0 || fld.Type.BitfieldLast() {
				size += fld.Size()
			}
		}
		align := typ.Align()
		if size%align != 0 {
			if typ.Varlen() {
				size += align - size%align
			} else {
				panic(fmt.Sprintf("struct %+v with type %+v has static size %v, which isn't aligned to %v", a, typ, size, align))
			}
		}
		return size
	case *sys.UnionType:
		if !typ.Varlen() {
			return typ.Size()
		} else {
			return a.Option.Size()
		}
	case *sys.ArrayType:
		var size uintptr
		for _, in := range a.Inner {
			size += in.Size()
		}
		return size
	default:
		panic("unknown arg type")
	}
}

func constArg(t sys.Type, v uintptr) *Arg {
	return &Arg{Type: t, Kind: ArgConst, Val: v}
}

func resultArg(t sys.Type, r *Arg) *Arg {
	arg := &Arg{Type: t, Kind: ArgResult, Res: r}
	if r.Uses == nil {
		r.Uses = make(map[*Arg]bool)
	}
	if r.Uses[arg] {
		panic("already used")
	}
	r.Uses[arg] = true
	return arg
}

func dataArg(t sys.Type, data []byte) *Arg {
	return &Arg{Type: t, Kind: ArgData, Data: append([]byte{}, data...)}
}

func pointerArg(t sys.Type, page uintptr, off int, npages uintptr, obj *Arg) *Arg {
	return &Arg{Type: t, Kind: ArgPointer, AddrPage: page, AddrOffset: off, AddrPagesNum: npages, Res: obj}
}

func pageSizeArg(t sys.Type, npages uintptr, off int) *Arg {
	return &Arg{Type: t, Kind: ArgPageSize, AddrPage: npages, AddrOffset: off}
}

func groupArg(t sys.Type, inner []*Arg) *Arg {
	return &Arg{Type: t, Kind: ArgGroup, Inner: inner}
}

func unionArg(t sys.Type, opt *Arg, typ sys.Type) *Arg {
	return &Arg{Type: t, Kind: ArgUnion, Option: opt, OptionType: typ}
}

func returnArg(t sys.Type) *Arg {
	if t != nil {
		return &Arg{Type: t, Kind: ArgReturn, Val: t.Default()}
	}
	return &Arg{Type: t, Kind: ArgReturn}
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
func (p *Prog) replaceArg(c *Call, arg, arg1 *Arg, calls []*Call) {
	if arg.Kind != ArgConst && arg.Kind != ArgResult && arg.Kind != ArgPointer && arg.Kind != ArgUnion {
		panic(fmt.Sprintf("replaceArg: bad arg kind %v", arg.Kind))
	}
	if arg1.Kind != ArgConst && arg1.Kind != ArgResult && arg1.Kind != ArgPointer && arg.Kind != ArgUnion {
		panic(fmt.Sprintf("replaceArg: bad arg1 kind %v", arg1.Kind))
	}
	if arg.Kind == ArgResult {
		delete(arg.Res.Uses, arg)
	}
	for _, c := range calls {
		sanitizeCall(c)
	}
	p.insertBefore(c, calls)
	// Somewhat hacky, but safe and preserves references to arg.
	uses := arg.Uses
	*arg = *arg1
	arg.Uses = uses
	if arg.Kind == ArgResult {
		delete(arg.Res.Uses, arg1)
		arg.Res.Uses[arg] = true
	}
	sanitizeCall(c)
}

// removeArg removes all references to/from arg0 of call c from p.
func (p *Prog) removeArg(c *Call, arg0 *Arg) {
	foreachSubarg(arg0, func(arg, _ *Arg, _ *[]*Arg) {
		if arg.Kind == ArgResult {
			if _, ok := arg.Res.Uses[arg]; !ok {
				panic("broken tree")
			}
			delete(arg.Res.Uses, arg)
		}
		for arg1 := range arg.Uses {
			if arg1.Kind != ArgResult {
				panic("use references not ArgResult")
			}
			arg2 := constArg(arg1.Type, arg1.Type.Default())
			p.replaceArg(c, arg1, arg2, nil)
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
