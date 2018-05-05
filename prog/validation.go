// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

var debug = false // enabled in tests

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
		if err := p.validateCall(ctx, c); err != nil {
			return err
		}
	}
	for u, orig := range ctx.uses {
		if !ctx.args[u] {
			return fmt.Errorf("use of %+v referes to an out-of-tree arg\narg: %#v", orig, u)
		}
	}
	return nil
}

func (p *Prog) validateCall(ctx *validCtx, c *Call) error {
	if c.Meta == nil {
		return fmt.Errorf("call does not have meta information")
	}
	if len(c.Args) != len(c.Meta.Args) {
		return fmt.Errorf("syscall %v: wrong number of arguments, want %v, got %v",
			c.Meta.Name, len(c.Meta.Args), len(c.Args))
	}
	for _, arg := range c.Args {
		if err := validateArg(ctx, c, arg); err != nil {
			return err
		}
	}
	if c.Meta.Ret == nil {
		if c.Ret != nil {
			return fmt.Errorf("syscall %v: return value without type", c.Meta.Name)
		}
	} else {
		if c.Ret == nil {
			return fmt.Errorf("syscall %v: return value is absent", c.Meta.Name)
		}
		if c.Ret.Type() != c.Meta.Ret {
			return fmt.Errorf("syscall %v: wrong return type", c.Meta.Name)
		}
		if c.Ret.Type().Dir() != DirOut {
			return fmt.Errorf("syscall %v: return value %v is not output", c.Meta.Name, c.Ret)
		}
		if c.Ret.Res != nil || c.Ret.Val != 0 || c.Ret.OpDiv != 0 || c.Ret.OpAdd != 0 {
			return fmt.Errorf("syscall %v: return value %v is not empty", c.Meta.Name, c.Ret)
		}
		if err := validateArg(ctx, c, c.Ret); err != nil {
			return err
		}
	}
	return nil
}

// nolint: gocyclo
func validateArg(ctx *validCtx, c *Call, arg Arg) error {
	if arg == nil {
		return fmt.Errorf("syscall %v: nil arg", c.Meta.Name)
	}
	if ctx.args[arg] {
		return fmt.Errorf("syscall %v: arg %#v is referenced several times in the tree",
			c.Meta.Name, arg)
	}
	ctx.args[arg] = true
	// TODO(dvyukov): move this to ResultArg verification.
	if used, ok := arg.(*ResultArg); ok {
		for u := range used.uses {
			if u == nil {
				return fmt.Errorf("syscall %v: nil reference in uses for arg %+v",
					c.Meta.Name, arg)
			}
			ctx.uses[u] = arg
		}
	}
	if arg.Type() == nil {
		return fmt.Errorf("syscall %v: no type", c.Meta.Name)
	}
	if arg.Type().Dir() == DirOut {
		switch a := arg.(type) {
		case *ConstArg:
			// We generate output len arguments, which makes sense since it can be
			// a length of a variable-length array which is not known otherwise.
			if _, ok := a.Type().(*LenType); ok {
				break
			}
			if a.Val != 0 && a.Val != a.Type().Default() {
				return fmt.Errorf("syscall %v: output arg '%v'/'%v' has non default value '%+v'",
					c.Meta.Name, a.Type().FieldName(), a.Type().Name(), a)
			}
		case *DataArg:
			if len(a.data) != 0 {
				return fmt.Errorf("syscall %v: output arg '%v' has data",
					c.Meta.Name, a.Type().Name())
			}
		}
	}

	switch typ1 := arg.Type().(type) {
	case *IntType:
		switch a := arg.(type) {
		case *ConstArg:
			if a.Type().Dir() == DirOut && (a.Val != 0 && a.Val != a.Type().Default()) {
				return fmt.Errorf("syscall %v: out int arg '%v' has bad const value %v",
					c.Meta.Name, a.Type().Name(), a.Val)
			}
		default:
			return fmt.Errorf("syscall %v: int arg '%v' has bad kind %v",
				c.Meta.Name, arg.Type().Name(), arg)
		}
	case *ResourceType:
		switch a := arg.(type) {
		case *ResultArg:
			if a.Type().Dir() == DirOut && (a.Val != 0 && a.Val != a.Type().Default()) {
				return fmt.Errorf("syscall %v: out resource arg '%v' has bad const value %v",
					c.Meta.Name, a.Type().Name(), a.Val)
			}
		default:
			return fmt.Errorf("syscall %v: fd arg '%v' has bad kind %v",
				c.Meta.Name, arg.Type().Name(), arg)
		}
	case *StructType, *ArrayType:
		switch arg.(type) {
		case *GroupArg:
		default:
			return fmt.Errorf("syscall %v: struct/array arg '%v' has bad kind %#v",
				c.Meta.Name, arg.Type().Name(), arg)
		}
	case *UnionType:
		switch arg.(type) {
		case *UnionArg:
		default:
			return fmt.Errorf("syscall %v: union arg '%v' has bad kind %v",
				c.Meta.Name, arg.Type().Name(), arg)
		}
	case *ProcType:
		switch a := arg.(type) {
		case *ConstArg:
			if a.Val >= typ1.ValuesPerProc && a.Val != typ1.Default() {
				return fmt.Errorf("syscall %v: per proc arg '%v' has bad value '%v'",
					c.Meta.Name, a.Type().Name(), a.Val)
			}
		default:
			return fmt.Errorf("syscall %v: proc arg '%v' has bad kind %v",
				c.Meta.Name, arg.Type().Name(), arg)
		}
	case *BufferType:
		switch a := arg.(type) {
		case *DataArg:
			switch typ1.Kind {
			case BufferString:
				if typ1.TypeSize != 0 && a.Size() != typ1.TypeSize {
					return fmt.Errorf("syscall %v: string arg '%v' has size %v, which should be %v",
						c.Meta.Name, a.Type().Name(), a.Size(), typ1.TypeSize)
				}
			}
		default:
			return fmt.Errorf("syscall %v: buffer arg '%v' has bad kind %v",
				c.Meta.Name, arg.Type().Name(), arg)
		}
	case *CsumType:
		switch a := arg.(type) {
		case *ConstArg:
			if a.Val != 0 {
				return fmt.Errorf("syscall %v: csum arg '%v' has nonzero value %v",
					c.Meta.Name, a.Type().Name(), a.Val)
			}
		default:
			return fmt.Errorf("syscall %v: csum arg '%v' has bad kind %v",
				c.Meta.Name, arg.Type().Name(), arg)
		}
	case *PtrType:
		switch a := arg.(type) {
		case *PointerArg:
			if a.Type().Dir() == DirOut {
				return fmt.Errorf("syscall %v: pointer arg '%v' has output direction",
					c.Meta.Name, a.Type().Name())
			}
			if a.Res == nil && !a.Type().Optional() {
				return fmt.Errorf("syscall %v: non optional pointer arg '%v' is nil",
					c.Meta.Name, a.Type().Name())
			}
		default:
			return fmt.Errorf("syscall %v: ptr arg '%v' has bad kind %v",
				c.Meta.Name, arg.Type().Name(), arg)
		}
	}

	switch a := arg.(type) {
	case *ConstArg:
	case *PointerArg:
		maxMem := ctx.target.NumPages * ctx.target.PageSize
		size := a.VmaSize
		if size == 0 && a.Res != nil {
			size = a.Res.Size()
		}
		if a.Address >= maxMem || a.Address+size > maxMem {
			return fmt.Errorf("syscall %v: ptr %v has bad address %v/%v/%v",
				c.Meta.Name, a.Type().Name(), a.Address, a.VmaSize, size)
		}
		switch t := a.Type().(type) {
		case *VmaType:
			if a.Res != nil {
				return fmt.Errorf("syscall %v: vma arg '%v' has data",
					c.Meta.Name, a.Type().Name())
			}
			if a.VmaSize == 0 && t.Dir() != DirOut && !t.Optional() {
				return fmt.Errorf("syscall %v: vma arg '%v' has size 0",
					c.Meta.Name, a.Type().Name())
			}
		case *PtrType:
			if a.Res != nil {
				if err := validateArg(ctx, c, a.Res); err != nil {
					return err
				}
			}
			if a.VmaSize != 0 {
				return fmt.Errorf("syscall %v: pointer arg '%v' has nonzero size",
					c.Meta.Name, a.Type().Name())
			}
		default:
			return fmt.Errorf("syscall %v: pointer arg '%v' has bad meta type %+v",
				c.Meta.Name, arg.Type().Name(), arg.Type())
		}
	case *DataArg:
		typ1 := a.Type()
		if !typ1.Varlen() && typ1.Size() != a.Size() {
			return fmt.Errorf("syscall %v: data arg %v has wrong size %v, want %v",
				c.Meta.Name, arg.Type().Name(), a.Size(), typ1.Size())
		}
	case *GroupArg:
		switch typ1 := a.Type().(type) {
		case *StructType:
			if len(a.Inner) != len(typ1.Fields) {
				return fmt.Errorf("syscall %v: struct arg '%v' has wrong number of fields: want %v, got %v",
					c.Meta.Name, a.Type().Name(), len(typ1.Fields), len(a.Inner))
			}
			for _, arg1 := range a.Inner {
				if err := validateArg(ctx, c, arg1); err != nil {
					return err
				}
			}
		case *ArrayType:
			if typ1.Kind == ArrayRangeLen && typ1.RangeBegin == typ1.RangeEnd &&
				uint64(len(a.Inner)) != typ1.RangeBegin {
				return fmt.Errorf("syscall %v: array %v has wrong number"+
					" of elements %v, want %v",
					c.Meta.Name, arg.Type().Name(),
					len(a.Inner), typ1.RangeBegin)
			}
			for _, arg1 := range a.Inner {
				if err := validateArg(ctx, c, arg1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("syscall %v: group arg '%v' has bad underlying type %+v",
				c.Meta.Name, arg.Type().Name(), arg.Type())
		}
	case *UnionArg:
		typ1, ok := a.Type().(*UnionType)
		if !ok {
			return fmt.Errorf("syscall %v: union arg '%v' has bad type",
				c.Meta.Name, a.Type().Name())
		}
		found := false
		for _, typ2 := range typ1.Fields {
			if a.Option.Type().Name() == typ2.Name() {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("syscall %v: union arg '%v' has bad option",
				c.Meta.Name, a.Type().Name())
		}
		if err := validateArg(ctx, c, a.Option); err != nil {
			return err
		}
	case *ResultArg:
		switch a.Type().(type) {
		case *ResourceType:
		default:
			return fmt.Errorf("syscall %v: result arg '%v' has bad meta type %+v",
				c.Meta.Name, arg.Type().Name(), arg.Type())
		}
		if a.Res == nil {
			break
		}
		if !ctx.args[a.Res] {
			return fmt.Errorf("syscall %v: result arg %v references out-of-tree result: %#v -> %#v",
				c.Meta.Name, a.Type().Name(), arg, a.Res)
		}
		if !a.Res.uses[a] {
			return fmt.Errorf("syscall %v: result arg '%v' has broken link (%+v)",
				c.Meta.Name, a.Type().Name(), a.Res.uses)
		}
	default:
		return fmt.Errorf("syscall %v: unknown arg '%v' kind",
			c.Meta.Name, arg.Type().Name())
	}
	return nil
}
