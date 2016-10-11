// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"

	"github.com/google/syzkaller/sys"
)

type validCtx struct {
	args map[*Arg]bool
	uses map[*Arg]*Arg
}

func (p *Prog) validate() error {
	ctx := &validCtx{make(map[*Arg]bool), make(map[*Arg]*Arg)}
	for _, c := range p.Calls {
		if err := c.validate(ctx); err != nil {
			return err
		}
	}
	for u, orig := range ctx.uses {
		if !ctx.args[u] {
			return fmt.Errorf("use of %+v referes to an out-of-tree arg\narg: %#v", *orig, u)
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
	var checkArg func(arg *Arg, typ sys.Type) error
	checkArg = func(arg *Arg, typ sys.Type) error {
		if arg == nil {
			return fmt.Errorf("syscall %v: nil arg", c.Meta.Name)
		}
		if arg.Call != c {
			return fmt.Errorf("syscall %v: arg has wrong call, call=%p, arg=%+v", c.Meta.Name, c, *arg)
		}
		if ctx.args[arg] {
			return fmt.Errorf("syscall %v: arg is referenced several times in the tree", c.Meta.Name)
		}
		ctx.args[arg] = true
		for u := range arg.Uses {
			ctx.uses[u] = arg
		}
		if arg.Type == nil {
			return fmt.Errorf("syscall %v: no type", c.Meta.Name)
		}
		if arg.Type.Name() != typ.Name() {
			return fmt.Errorf("syscall %v: arg '%v' type mismatch", c.Meta.Name, typ.Name())
		}
		if arg.Dir == DirOut {
			if arg.Val != 0 || arg.AddrPage != 0 || arg.AddrOffset != 0 {
				return fmt.Errorf("syscall %v: output arg '%v' has data", c.Meta.Name, typ.Name())
			}
			for _, v := range arg.Data {
				if v != 0 {
					return fmt.Errorf("syscall %v: output arg '%v' has data", c.Meta.Name, typ.Name())
				}
			}
		}
		switch arg.Type.(type) {
		case sys.ResourceType:
			switch arg.Kind {
			case ArgResult:
			case ArgReturn:
			case ArgConst:
				if arg.Dir == DirOut && arg.Val != 0 {
					return fmt.Errorf("syscall %v: out resource arg '%v' has bad const value %v", c.Meta.Name, typ.Name(), arg.Val)
				}
			default:
				return fmt.Errorf("syscall %v: fd arg '%v' has bad kind %v", c.Meta.Name, typ.Name(), arg.Kind)
			}
		case sys.FilenameType:
			switch arg.Kind {
			case ArgData:
			default:
				return fmt.Errorf("syscall %v: filename arg '%v' has bad kind %v", c.Meta.Name, typ.Name(), arg.Kind)
			}
		case *sys.StructType, *sys.ArrayType:
			switch arg.Kind {
			case ArgGroup:
			default:
				return fmt.Errorf("syscall %v: struct/array arg '%v' has bad kind %v", c.Meta.Name, typ.Name(), arg.Kind)
			}
		case *sys.UnionType:
			switch arg.Kind {
			case ArgUnion:
			default:
				return fmt.Errorf("syscall %v: union arg '%v' has bad kind %v", c.Meta.Name, typ.Name(), arg.Kind)
			}
		}
		switch arg.Kind {
		case ArgConst:
		case ArgResult:
			if arg.Res == nil {
				return fmt.Errorf("syscall %v: result arg '%v' has no reference", c.Meta.Name, typ.Name())
			}
			if !ctx.args[arg.Res] {
				return fmt.Errorf("syscall %v: result arg '%v' references out-of-tree result: %p%+v -> %v %p%+v",
					c.Meta.Name, typ.Name(), arg, arg, arg.Res.Call.Meta.Name, arg.Res, arg.Res)
			}
			if _, ok := arg.Res.Uses[arg]; !ok {
				return fmt.Errorf("syscall %v: result arg '%v' has broken link (%+v)", c.Meta.Name, typ.Name(), arg.Res.Uses)
			}
		case ArgPointer:
			if arg.Dir != DirIn {
				return fmt.Errorf("syscall %v: pointer arg '%v' has output direction", c.Meta.Name, typ.Name())
			}
			switch typ1 := typ.(type) {
			case sys.VmaType:
				if arg.Res != nil {
					return fmt.Errorf("syscall %v: vma arg '%v' has data", c.Meta.Name, typ.Name())
				}
				if arg.AddrPagesNum == 0 {
					return fmt.Errorf("syscall %v: vma arg '%v' has size 0", c.Meta.Name, typ.Name())
				}
			case sys.PtrType:
				if arg.Res != nil {
					if err := checkArg(arg.Res, typ1.Type); err != nil {
						return err
					}
				}
				if arg.AddrPagesNum != 0 {
					return fmt.Errorf("syscall %v: pointer arg '%v' has nonzero size", c.Meta.Name, typ.Name())
				}
			default:
				return fmt.Errorf("syscall %v: pointer arg '%v' has bad meta type %+v", c.Meta.Name, typ.Name(), typ)
			}
		case ArgPageSize:
		case ArgData:
		case ArgGroup:
			switch typ1 := typ.(type) {
			case *sys.StructType:
				if len(arg.Inner) != len(typ1.Fields) {
					return fmt.Errorf("syscall %v: struct arg '%v' has wrong number of fields: want %v, got %v", c.Meta.Name, typ.Name(), len(typ1.Fields), len(arg.Inner))
				}
				for i, arg1 := range arg.Inner {
					if err := checkArg(arg1, typ1.Fields[i]); err != nil {
						return err
					}
				}
			case sys.ArrayType:
				for _, arg1 := range arg.Inner {
					if err := checkArg(arg1, typ1.Type); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("syscall %v: group arg '%v' has bad underlying type %+v", c.Meta.Name, typ.Name(), typ)
			}
		case ArgUnion:
			typ1, ok := typ.(*sys.UnionType)
			if !ok {
				return fmt.Errorf("syscall %v: union arg '%v' has bad type", c.Meta.Name, typ.Name())
			}
			found := false
			for _, typ2 := range typ1.Options {
				if arg.OptionType.Name() == typ2.Name() {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("syscall %v: union arg '%v' has bad option", c.Meta.Name, typ.Name())
			}
			if err := checkArg(arg.Option, arg.OptionType); err != nil {
				return err
			}
		case ArgReturn:
		default:
			return fmt.Errorf("syscall %v: unknown arg '%v' kind", c.Meta.Name, typ.Name())
		}
		return nil
	}
	for i, arg := range c.Args {
		if c.Ret.Kind != ArgReturn {
			return fmt.Errorf("syscall %v: arg '%v' has wrong return kind", c.Meta.Name, arg.Type.Name())
		}
		if err := checkArg(arg, c.Meta.Args[i]); err != nil {
			return err
		}
	}
	if c.Ret == nil {
		return fmt.Errorf("syscall %v: return value is absent", c.Meta.Name)
	}
	if c.Ret.Kind != ArgReturn {
		return fmt.Errorf("syscall %v: return value has wrong kind %v", c.Meta.Name, c.Ret.Kind)
	}
	if c.Meta.Ret != nil {
		if err := checkArg(c.Ret, c.Meta.Ret); err != nil {
			return err
		}
	} else if c.Ret.Type != nil {
		return fmt.Errorf("syscall %v: return value has spurious type: %+v", c.Meta.Name, c.Ret.Type)
	}
	return nil
}
