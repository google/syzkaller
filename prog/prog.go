// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
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
	Call       *Call
	Type       sys.Type
	Kind       ArgKind
	Dir        ArgDir
	Val        uintptr       // value of ArgConst
	AddrPage   uintptr       // page index for ArgPointer address, page count for ArgPageSize
	AddrOffset int           // page offset for ArgPointer address
	Data       []byte        // data of ArgData
	Inner      []*Arg        // subargs of ArgGroup
	Res        *Arg          // target of ArgResult, pointee for ArgPointer
	Uses       map[*Arg]bool // this arg is used by those ArgResult args
	OpDiv      uintptr       // divide result for ArgResult (executed before OpAdd)
	OpAdd      uintptr       // add to result for ArgResult
}

type ArgKind int

const (
	ArgConst ArgKind = iota
	ArgResult
	ArgPointer  // even if these are always constant (for reproducibility), we use a separate type because they are represented in an abstract (base+page+offset) form
	ArgPageSize // same as ArgPointer but base is not added, so it represents "lengths" in pages
	ArgData
	ArgGroup  // logical group of args (struct or array)
	ArgReturn // fake value denoting syscall return value
)

type ArgDir sys.Dir

const (
	DirIn    = ArgDir(sys.DirIn)
	DirOut   = ArgDir(sys.DirOut)
	DirInOut = ArgDir(sys.DirInOut)
)

func (a *Arg) Size(typ sys.Type) uintptr {
	switch typ1 := typ.(type) {
	case sys.IntType:
		return typ1.TypeSize
	case sys.LenType:
		return typ1.TypeSize
	case sys.FlagsType:
		return typ1.TypeSize
	case sys.ConstType:
		return typ1.TypeSize
	case sys.FileoffType:
		return typ1.TypeSize
	case sys.ResourceType:
		return typ1.Size()
	case sys.VmaType:
		return ptrSize
	case sys.FilenameType:
		return uintptr(len(a.Data))
	case sys.PtrType:
		return ptrSize
	case sys.StructType:
		var size uintptr
		for i, f := range typ1.Fields {
			size += a.Inner[i].Size(f)
		}
		return size
	case sys.ArrayType:
		if len(a.Inner) == 0 {
			return 0
		}
		return uintptr(len(a.Inner)) * a.Inner[0].Size(typ1.Type)
	case sys.BufferType:
		return uintptr(len(a.Data))
	default:
		panic("unknown arg type")
	}
}

func constArg(v uintptr) *Arg {
	return &Arg{Kind: ArgConst, Val: v}
}

func resultArg(r *Arg) *Arg {
	arg := &Arg{Kind: ArgResult, Res: r}
	if r.Uses == nil {
		r.Uses = make(map[*Arg]bool)
	}
	if r.Uses[arg] {
		panic("already used")
	}
	r.Uses[arg] = true
	return arg
}

func dataArg(data []byte) *Arg {
	return &Arg{Kind: ArgData, Data: append([]byte{}, data...)}
}

func pointerArg(page uintptr, off int, obj *Arg) *Arg {
	return &Arg{Kind: ArgPointer, AddrPage: page, AddrOffset: off, Res: obj}
}

func pageSizeArg(npages uintptr, off int) *Arg {
	return &Arg{Kind: ArgPageSize, AddrPage: npages, AddrOffset: off}
}

func groupArg(inner []*Arg) *Arg {
	return &Arg{Kind: ArgGroup, Inner: inner}
}

func returnArg() *Arg {
	return &Arg{Kind: ArgReturn, Dir: DirOut}
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
