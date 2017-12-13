// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

func (p *Prog) Clone() *Prog {
	p1 := &Prog{
		Target: p.Target,
		Calls:  make([]*Call, len(p.Calls)),
	}
	newargs := make(map[Arg]Arg)
	for ci, c := range p.Calls {
		c1 := new(Call)
		c1.Meta = c.Meta
		c1.Ret = clone(c.Ret, newargs)
		c1.Args = make([]Arg, len(c.Args))
		for ai, arg := range c.Args {
			c1.Args[ai] = clone(arg, newargs)
		}
		p1.Calls[ci] = c1
	}
	if debug {
		if err := p1.validate(); err != nil {
			panic(err)
		}
	}
	return p1
}

func clone(arg Arg, newargs map[Arg]Arg) Arg {
	var arg1 Arg
	switch a := arg.(type) {
	case *ConstArg:
		a1 := new(ConstArg)
		*a1 = *a
		arg1 = a1
	case *PointerArg:
		a1 := new(PointerArg)
		*a1 = *a
		arg1 = a1
		if a.Res != nil {
			a1.Res = clone(a.Res, newargs)
		}
	case *DataArg:
		a1 := new(DataArg)
		*a1 = *a
		a1.data = append([]byte{}, a.data...)
		arg1 = a1
	case *GroupArg:
		a1 := new(GroupArg)
		*a1 = *a
		arg1 = a1
		a1.Inner = make([]Arg, len(a.Inner))
		for i, arg2 := range a.Inner {
			a1.Inner[i] = clone(arg2, newargs)
		}
	case *UnionArg:
		a1 := new(UnionArg)
		*a1 = *a
		arg1 = a1
		a1.Option = clone(a.Option, newargs)
	case *ResultArg:
		a1 := new(ResultArg)
		*a1 = *a
		arg1 = a1
	case *ReturnArg:
		a1 := new(ReturnArg)
		*a1 = *a
		arg1 = a1
	default:
		panic("bad arg kind")
	}
	if user, ok := arg1.(ArgUser); ok && *user.Uses() != nil {
		r := newargs[*user.Uses()]
		*user.Uses() = r
		used := r.(ArgUsed)
		if *used.Used() == nil {
			*used.Used() = make(map[Arg]bool)
		}
		(*used.Used())[arg1] = true
	}
	if used, ok := arg1.(ArgUsed); ok {
		*used.Used() = nil // filled when we clone the referent
		newargs[arg] = arg1
	}
	return arg1
}
