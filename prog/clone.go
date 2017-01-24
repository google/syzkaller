// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

func (p *Prog) Clone() *Prog {
	p1 := new(Prog)
	newargs := make(map[*Arg]*Arg)
	for _, c := range p.Calls {
		c1 := new(Call)
		c1.Meta = c.Meta
		c1.Ret = c.Ret.clone(c1, newargs)
		for _, arg := range c.Args {
			c1.Args = append(c1.Args, arg.clone(c1, newargs))
		}
		p1.Calls = append(p1.Calls, c1)
	}
	if debug {
		if err := p1.validate(); err != nil {
			panic(err)
		}
	}
	return p1
}

func (arg *Arg) clone(c *Call, newargs map[*Arg]*Arg) *Arg {
	arg1 := new(Arg)
	*arg1 = *arg
	arg1.Data = append([]byte{}, arg.Data...)
	switch arg.Kind {
	case ArgPointer:
		if arg.Res != nil {
			arg1.Res = arg.Res.clone(c, newargs)
		}
	case ArgUnion:
		arg1.Option = arg.Option.clone(c, newargs)
	case ArgResult:
		r := newargs[arg.Res]
		arg1.Res = r
		if r.Uses == nil {
			r.Uses = make(map[*Arg]bool)
		}
		r.Uses[arg1] = true
	}
	arg1.Inner = nil
	for _, arg2 := range arg.Inner {
		arg1.Inner = append(arg1.Inner, arg2.clone(c, newargs))
	}
	if len(arg1.Uses) != 0 {
		arg1.Uses = nil // filled when we clone the referent
		newargs[arg] = arg1
	}
	return arg1
}
