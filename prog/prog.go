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
	Call         *Call
	Type         sys.Type
	Kind         ArgKind
	Dir          ArgDir
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

type ArgDir sys.Dir

const (
	DirIn    = ArgDir(sys.DirIn)
	DirOut   = ArgDir(sys.DirOut)
	DirInOut = ArgDir(sys.DirInOut)
)

// Returns inner arg for PtrType args
func (a *Arg) InnerArg(typ sys.Type) *Arg {
	switch typ1 := typ.(type) {
	case sys.PtrType:
		if a.Res == nil {
			if typ.Optional() {
				return nil
			} else {
				panic(fmt.Sprintf("non-optional pointer is nil\narg: %+v\ntype: %+v", a, typ1))
			}
		} else {
			return a.Res.InnerArg(typ1.Type)
		}
	default:
		return a
	}
}

func (a *Arg) Size(typ sys.Type) uintptr {
	switch typ1 := typ.(type) {
	case sys.IntType, sys.LenType, sys.FlagsType, sys.ConstType, sys.StrConstType,
		sys.FileoffType, sys.ResourceType, sys.VmaType, sys.PtrType:
		return typ.Size()
	case sys.FilenameType:
		return uintptr(len(a.Data))
	case sys.BufferType:
		return uintptr(len(a.Data))
	case *sys.StructType:
		var size uintptr
		for i, f := range typ1.Fields {
			size += a.Inner[i].Size(f)
		}
		return size
	case *sys.UnionType:
		return a.Option.Size(a.OptionType)
	case sys.ArrayType:
		var size uintptr
		for _, in := range a.Inner {
			size += in.Size(typ1.Type)
		}
		return size
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

func pointerArg(page uintptr, off int, npages uintptr, obj *Arg) *Arg {
	return &Arg{Kind: ArgPointer, AddrPage: page, AddrOffset: off, AddrPagesNum: npages, Res: obj}
}

func pageSizeArg(npages uintptr, off int) *Arg {
	return &Arg{Kind: ArgPageSize, AddrPage: npages, AddrOffset: off}
}

func groupArg(inner []*Arg) *Arg {
	return &Arg{Kind: ArgGroup, Inner: inner}
}

func unionArg(opt *Arg, typ sys.Type) *Arg {
	return &Arg{Kind: ArgUnion, Option: opt, OptionType: typ}
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

// replaceArg replaces arg with arg1 in p, and inserts calls before arg call.
func (p *Prog) replaceArg(arg, arg1 *Arg, calls []*Call) {
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
		assignTypeAndDir(c)
		sanitizeCall(c)
	}
	c := arg.Call
	p.insertBefore(c, calls)
	// Somewhat hacky, but safe and preserves references to arg.
	uses := arg.Uses
	*arg = *arg1
	arg.Uses = uses
	if arg.Kind == ArgResult {
		delete(arg.Res.Uses, arg1)
		arg.Res.Uses[arg] = true
	}
	assignTypeAndDir(c)
	sanitizeCall(c)
}

// removeArg removes all references to/from arg0 from p.
func (p *Prog) removeArg(arg0 *Arg) {
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
			arg2 := constArg(arg1.Type.Default())
			p.replaceArg(arg1, arg2, nil)
		}
	})
}

// removeCall removes call idx from p.
func (p *Prog) removeCall(idx int) {
	c := p.Calls[idx]
	copy(p.Calls[idx:], p.Calls[idx+1:])
	p.Calls = p.Calls[:len(p.Calls)-1]
	for _, arg := range c.Args {
		p.removeArg(arg)
	}
	p.removeArg(c.Ret)
}
