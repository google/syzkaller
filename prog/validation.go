// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

var debug = false // enabled in tests

type validCtx struct {
	args map[Arg]bool
	uses map[Arg]Arg
}

func (p *Prog) validate() error {
	ctx := &validCtx{make(map[Arg]bool), make(map[Arg]Arg)}
	for _, c := range p.Calls {
		if err := c.validate(ctx); err != nil {
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

func (c *Call) validate(ctx *validCtx) error {
	if c.Meta == nil {
		return fmt.Errorf("call does not have meta information")
	}
	if len(c.Args) != len(c.Meta.Args) {
		return fmt.Errorf("syscall %v: wrong number of arguments, want %v, got %v", c.Meta.Name, len(c.Meta.Args), len(c.Args))
	}
	var checkArg func(arg Arg) error
	checkArg = func(arg Arg) error {
		if arg == nil {
			return fmt.Errorf("syscall %v: nil arg", c.Meta.Name)
		}
		if ctx.args[arg] {
			return fmt.Errorf("syscall %v: arg is referenced several times in the tree", c.Meta.Name)
		}
		ctx.args[arg] = true
		if used, ok := arg.(ArgUsed); ok {
			for u := range *used.Used() {
				if u == nil {
					return fmt.Errorf("syscall %v: nil reference in uses for arg %+v", c.Meta.Name, arg)
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
					return fmt.Errorf("syscall %v: output arg '%v'/'%v' has non default value '%+v'", c.Meta.Name, a.Type().FieldName(), a.Type().Name(), a)
				}
			case *DataArg:
				for _, v := range a.Data {
					if v != 0 {
						return fmt.Errorf("syscall %v: output arg '%v' has data", c.Meta.Name, a.Type().Name())
					}
				}
			}
		}
		switch typ1 := arg.Type().(type) {
		case *IntType:
			switch a := arg.(type) {
			case *ConstArg:
				if a.Type().Dir() == DirOut && (a.Val != 0 && a.Val != a.Type().Default()) {
					return fmt.Errorf("syscall %v: out int arg '%v' has bad const value %v", c.Meta.Name, a.Type().Name(), a.Val)
				}
			case *ReturnArg:
			default:
				return fmt.Errorf("syscall %v: int arg '%v' has bad kind %v", c.Meta.Name, arg.Type().Name(), arg)
			}
		case *ResourceType:
			switch a := arg.(type) {
			case *ResultArg:
				if a.Type().Dir() == DirOut && (a.Val != 0 && a.Val != a.Type().Default()) {
					return fmt.Errorf("syscall %v: out resource arg '%v' has bad const value %v", c.Meta.Name, a.Type().Name(), a.Val)
				}
			case *ReturnArg:
			default:
				return fmt.Errorf("syscall %v: fd arg '%v' has bad kind %v", c.Meta.Name, arg.Type().Name(), arg)
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
				return fmt.Errorf("syscall %v: union arg '%v' has bad kind %v", c.Meta.Name, arg.Type().Name(), arg)
			}
		case *ProcType:
			switch a := arg.(type) {
			case *ConstArg:
				if a.Val >= typ1.ValuesPerProc {
					return fmt.Errorf("syscall %v: per proc arg '%v' has bad value '%v'", c.Meta.Name, a.Type().Name(), a.Val)
				}
			default:
				return fmt.Errorf("syscall %v: proc arg '%v' has bad kind %v", c.Meta.Name, arg.Type().Name(), arg)
			}
		case *BufferType:
			switch a := arg.(type) {
			case *DataArg:
				switch typ1.Kind {
				case BufferString:
					if typ1.TypeSize != 0 && uint64(len(a.Data)) != typ1.TypeSize {
						return fmt.Errorf("syscall %v: string arg '%v' has size %v, which should be %v",
							c.Meta.Name, a.Type().Name(), len(a.Data), typ1.TypeSize)
					}
				}
			default:
				return fmt.Errorf("syscall %v: buffer arg '%v' has bad kind %v", c.Meta.Name, arg.Type().Name(), arg)
			}
		case *CsumType:
			switch a := arg.(type) {
			case *ConstArg:
				if a.Val != 0 {
					return fmt.Errorf("syscall %v: csum arg '%v' has nonzero value %v", c.Meta.Name, a.Type().Name(), a.Val)
				}
			default:
				return fmt.Errorf("syscall %v: csum arg '%v' has bad kind %v", c.Meta.Name, arg.Type().Name(), arg)
			}
		case *PtrType:
			switch a := arg.(type) {
			case *PointerArg:
				if a.Type().Dir() == DirOut {
					return fmt.Errorf("syscall %v: pointer arg '%v' has output direction", c.Meta.Name, a.Type().Name())
				}
				if a.Res == nil && !a.Type().Optional() {
					return fmt.Errorf("syscall %v: non optional pointer arg '%v' is nil", c.Meta.Name, a.Type().Name())
				}
			default:
				return fmt.Errorf("syscall %v: ptr arg '%v' has bad kind %v", c.Meta.Name, arg.Type().Name(), arg)
			}
		}
		switch a := arg.(type) {
		case *ConstArg:
		case *PointerArg:
			switch t := a.Type().(type) {
			case *VmaType:
				if a.Res != nil {
					return fmt.Errorf("syscall %v: vma arg '%v' has data", c.Meta.Name, a.Type().Name())
				}
				if a.PagesNum == 0 && t.Dir() != DirOut && !t.Optional() {
					return fmt.Errorf("syscall %v: vma arg '%v' has size 0", c.Meta.Name, a.Type().Name())
				}
			case *PtrType:
				if a.Res != nil {
					if err := checkArg(a.Res); err != nil {
						return err
					}
				}
				if a.PagesNum != 0 {
					return fmt.Errorf("syscall %v: pointer arg '%v' has nonzero size", c.Meta.Name, a.Type().Name())
				}
			default:
				return fmt.Errorf("syscall %v: pointer arg '%v' has bad meta type %+v", c.Meta.Name, arg.Type().Name(), arg.Type())
			}
		case *DataArg:
			switch typ1 := a.Type().(type) {
			case *ArrayType:
				if typ2, ok := typ1.Type.(*IntType); !ok || typ2.Size() != 1 {
					return fmt.Errorf("syscall %v: data arg '%v' should be an array", c.Meta.Name, a.Type().Name())
				}
			}
		case *GroupArg:
			switch typ1 := a.Type().(type) {
			case *StructType:
				if len(a.Inner) != len(typ1.Fields) {
					return fmt.Errorf("syscall %v: struct arg '%v' has wrong number of fields: want %v, got %v", c.Meta.Name, a.Type().Name(), len(typ1.Fields), len(a.Inner))
				}
				for _, arg1 := range a.Inner {
					if err := checkArg(arg1); err != nil {
						return err
					}
				}
			case *ArrayType:
				for _, arg1 := range a.Inner {
					if err := checkArg(arg1); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("syscall %v: group arg '%v' has bad underlying type %+v", c.Meta.Name, arg.Type().Name(), arg.Type())
			}
		case *UnionArg:
			typ1, ok := a.Type().(*UnionType)
			if !ok {
				return fmt.Errorf("syscall %v: union arg '%v' has bad type", c.Meta.Name, a.Type().Name())
			}
			found := false
			for _, typ2 := range typ1.Fields {
				if a.OptionType.Name() == typ2.Name() {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("syscall %v: union arg '%v' has bad option", c.Meta.Name, a.Type().Name())
			}
			if err := checkArg(a.Option); err != nil {
				return err
			}
		case *ResultArg:
			switch a.Type().(type) {
			case *ResourceType:
			default:
				return fmt.Errorf("syscall %v: result arg '%v' has bad meta type %+v", c.Meta.Name, arg.Type().Name(), arg.Type())
			}
			if a.Res == nil {
				break
			}
			if !ctx.args[a.Res] {
				return fmt.Errorf("syscall %v: result arg '%v' references out-of-tree result: %p%+v -> %p%+v",
					c.Meta.Name, a.Type().Name(), arg, arg, a.Res, a.Res)
			}
			if _, ok := (*a.Res.(ArgUsed).Used())[arg]; !ok {
				return fmt.Errorf("syscall %v: result arg '%v' has broken link (%+v)", c.Meta.Name, a.Type().Name(), *a.Res.(ArgUsed).Used())
			}
		case *ReturnArg:
			switch a.Type().(type) {
			case *ResourceType:
			case *VmaType:
			default:
				return fmt.Errorf("syscall %v: result arg '%v' has bad meta type %+v", c.Meta.Name, arg.Type().Name(), arg.Type())
			}
		default:
			return fmt.Errorf("syscall %v: unknown arg '%v' kind", c.Meta.Name, arg.Type().Name())
		}
		return nil
	}
	for _, arg := range c.Args {
		if _, ok := arg.(*ReturnArg); ok {
			return fmt.Errorf("syscall %v: arg '%v' has wrong return kind", c.Meta.Name, arg.Type().Name())
		}
		if err := checkArg(arg); err != nil {
			return err
		}
	}
	if c.Ret == nil {
		return fmt.Errorf("syscall %v: return value is absent", c.Meta.Name)
	}
	if _, ok := c.Ret.(*ReturnArg); !ok {
		return fmt.Errorf("syscall %v: return value has wrong kind %v", c.Meta.Name, c.Ret)
	}
	if c.Meta.Ret != nil {
		if err := checkArg(c.Ret); err != nil {
			return err
		}
	} else if c.Ret.Type() != nil {
		return fmt.Errorf("syscall %v: return value has spurious type: %+v", c.Meta.Name, c.Ret.Type())
	}
	return nil
}
