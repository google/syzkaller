// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

var debug = false // enabled in tests and fuzzers

func Debug() {
	debug = true
}

func (p *Prog) debugValidate() {
	if debug {
		if err := p.validate(); err != nil {
			panic(err)
		}
	}
}

type validCtx struct {
	target *Target
	args   map[Arg]bool
	uses   map[Arg]Arg
}

func (p *Prog) validate() error {
	ctx := &validCtx{
		target: p.Target,
		args:   make(map[Arg]bool),
		uses:   make(map[Arg]Arg),
	}
	for _, c := range p.Calls {
		if c.Meta == nil {
			return fmt.Errorf("call does not have meta information")
		}
		if err := ctx.validateCall(c); err != nil {
			return fmt.Errorf("call %v: %v", c.Meta.Name, err)
		}
	}
	for u, orig := range ctx.uses {
		if !ctx.args[u] {
			return fmt.Errorf("use of %+v referes to an out-of-tree arg\narg: %#v", orig, u)
		}
	}
	return nil
}

func (ctx *validCtx) validateCall(c *Call) error {
	if c.Meta.Attrs.Disabled {
		return fmt.Errorf("use of a disabled call")
	}
	if len(c.Args) != len(c.Meta.Args) {
		return fmt.Errorf("wrong number of arguments, want %v, got %v",
			len(c.Meta.Args), len(c.Args))
	}
	for i, arg := range c.Args {
		if err := ctx.validateArg(arg, c.Meta.Args[i].Type, DirIn); err != nil {
			return err
		}
	}
	return ctx.validateRet(c)
}

func (ctx *validCtx) validateRet(c *Call) error {
	if c.Meta.Ret == nil {
		if c.Ret != nil {
			return fmt.Errorf("return value without type")
		}
		return nil
	}
	if c.Ret == nil {
		return fmt.Errorf("return value is absent")
	}
	if c.Ret.Res != nil || c.Ret.Val != 0 || c.Ret.OpDiv != 0 || c.Ret.OpAdd != 0 {
		return fmt.Errorf("return value %v is not empty", c.Ret)
	}
	return ctx.validateArg(c.Ret, c.Meta.Ret, DirOut)
}

func (ctx *validCtx) validateArg(arg Arg, typ Type, dir Dir) error {
	if arg == nil {
		return fmt.Errorf("nil arg")
	}
	if ctx.args[arg] {
		return fmt.Errorf("arg %#v is referenced several times in the tree", arg)
	}
	if arg.Type() == nil {
		return fmt.Errorf("no arg type")
	}
	if _, ok := typ.(*PtrType); ok {
		dir = DirIn // pointers are always in
	}
	if arg.Dir() != dir {
		return fmt.Errorf("arg %#v type %v has wrong dir %v, expect %v", arg, arg.Type(), arg.Dir(), dir)
	}
	if !ctx.target.isAnyPtr(arg.Type()) && arg.Type() != typ {
		return fmt.Errorf("bad arg type %#v, expect %#v", arg.Type(), typ)
	}
	ctx.args[arg] = true
	return arg.validate(ctx)
}

func (arg *ConstArg) validate(ctx *validCtx) error {
	switch typ := arg.Type().(type) {
	case *IntType:
		if arg.Dir() == DirOut && !isDefault(arg) {
			return fmt.Errorf("out int arg '%v' has bad const value %v", typ.Name(), arg.Val)
		}
	case *ProcType:
		if arg.Val >= typ.ValuesPerProc && !isDefault(arg) {
			return fmt.Errorf("per proc arg '%v' has bad value %v", typ.Name(), arg.Val)
		}
	case *CsumType:
		if arg.Val != 0 {
			return fmt.Errorf("csum arg '%v' has nonzero value %v", typ.Name(), arg.Val)
		}
	case *ConstType, *FlagsType, *LenType:
	default:
		return fmt.Errorf("const arg %v has bad type %v", arg, typ.Name())
	}
	if arg.Dir() == DirOut {
		// We generate output len arguments, which makes sense since it can be
		// a length of a variable-length array which is not known otherwise.
		typ := arg.Type()
		if _, isLen := typ.(*LenType); !isLen {
			if !typ.isDefaultArg(arg) {
				return fmt.Errorf("output arg %q has non default value %+v", typ.Name(), arg)
			}
		}
	}
	return nil
}

func (arg *ResultArg) validate(ctx *validCtx) error {
	typ, ok := arg.Type().(*ResourceType)
	if !ok {
		return fmt.Errorf("result arg %v has bad type %v", arg, arg.Type().Name())
	}
	for u := range arg.uses {
		if u == nil {
			return fmt.Errorf("nil reference in uses for arg %+v", arg)
		}
		if u.Res != arg {
			return fmt.Errorf("result arg '%v' has broken uses link to (%+v)", arg, u)
		}
		ctx.uses[u] = arg
	}
	if arg.Dir() == DirOut && arg.Val != 0 && arg.Val != typ.Default() {
		return fmt.Errorf("out resource arg '%v' has bad const value %v", typ.Name(), arg.Val)
	}
	if arg.Res != nil {
		if !ctx.args[arg.Res] {
			return fmt.Errorf("result arg %v references out-of-tree result: %#v -> %#v",
				typ.Name(), arg, arg.Res)
		}
		if !arg.Res.uses[arg] {
			return fmt.Errorf("result arg '%v' has broken link (%+v)", typ.Name(), arg.Res.uses)
		}
	}
	return nil
}

func (arg *DataArg) validate(ctx *validCtx) error {
	typ, ok := arg.Type().(*BufferType)
	if !ok {
		return fmt.Errorf("data arg %v has bad type %v", arg, arg.Type().Name())
	}
	if arg.Dir() == DirOut && len(arg.data) != 0 {
		return fmt.Errorf("output arg '%v' has data", typ.Name())
	}
	if !typ.Varlen() && typ.Size() != arg.Size() {
		return fmt.Errorf("data arg %v has wrong size %v, want %v",
			typ.Name(), arg.Size(), typ.Size())
	}
	switch typ.Kind {
	case BufferString:
		if typ.TypeSize != 0 && arg.Size() != typ.TypeSize {
			return fmt.Errorf("string arg '%v' has size %v, which should be %v",
				typ.Name(), arg.Size(), typ.TypeSize)
		}
	}
	return nil
}

func (arg *GroupArg) validate(ctx *validCtx) error {
	switch typ := arg.Type().(type) {
	case *StructType:
		if len(arg.Inner) != len(typ.Fields) {
			return fmt.Errorf("struct arg '%v' has wrong number of fields: want %v, got %v",
				typ.Name(), len(typ.Fields), len(arg.Inner))
		}
		for i, field := range arg.Inner {
			if err := ctx.validateArg(field, typ.Fields[i].Type, typ.Fields[i].Dir(arg.Dir())); err != nil {
				return err
			}
		}
	case *ArrayType:
		if typ.Kind == ArrayRangeLen && typ.RangeBegin == typ.RangeEnd &&
			uint64(len(arg.Inner)) != typ.RangeBegin {
			return fmt.Errorf("array %v has wrong number of elements %v, want %v",
				typ.Name(), len(arg.Inner), typ.RangeBegin)
		}
		for _, elem := range arg.Inner {
			if err := ctx.validateArg(elem, typ.Elem, arg.Dir()); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("group arg %v has bad type %v", arg, typ.Name())
	}
	return nil
}

func (arg *UnionArg) validate(ctx *validCtx) error {
	typ, ok := arg.Type().(*UnionType)
	if !ok {
		return fmt.Errorf("union arg %v has bad type %v", arg, arg.Type().Name())
	}
	if arg.Index < 0 || arg.Index >= len(typ.Fields) {
		return fmt.Errorf("union arg %v has bad index %v/%v", arg, arg.Index, len(typ.Fields))
	}
	opt := typ.Fields[arg.Index]
	return ctx.validateArg(arg.Option, opt.Type, opt.Dir(arg.Dir()))
}

func (arg *PointerArg) validate(ctx *validCtx) error {
	switch typ := arg.Type().(type) {
	case *VmaType:
		if arg.Res != nil {
			return fmt.Errorf("vma arg '%v' has data", typ.Name())
		}
	case *PtrType:
		if arg.Res != nil {
			if err := ctx.validateArg(arg.Res, typ.Elem, typ.ElemDir); err != nil {
				return err
			}
		}
		if arg.VmaSize != 0 {
			return fmt.Errorf("pointer arg '%v' has nonzero size", typ.Name())
		}
		if arg.Dir() == DirOut {
			return fmt.Errorf("pointer arg '%v' has output direction", typ.Name())
		}
	default:
		return fmt.Errorf("ptr arg %v has bad type %v", arg, typ.Name())
	}
	if arg.IsSpecial() {
		if -arg.Address >= uint64(len(ctx.target.SpecialPointers)) {
			return fmt.Errorf("special ptr arg %v has bad value 0x%x", arg.Type().Name(), arg.Address)
		}
	} else {
		maxMem := ctx.target.NumPages * ctx.target.PageSize
		size := arg.VmaSize
		if size == 0 && arg.Res != nil {
			size = arg.Res.Size()
		}
		if arg.Address >= maxMem || arg.Address+size > maxMem {
			return fmt.Errorf("ptr %v has bad address %v/%v/%v",
				arg.Type().Name(), arg.Address, arg.VmaSize, size)
		}
	}
	return nil
}
