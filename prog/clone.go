// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

func (p *Prog) Clone() *Prog {
	newargs := make(map[*ResultArg]*ResultArg)
	p1 := &Prog{
		Target: p.Target,
		Calls:  cloneCalls(p.Calls, newargs),
	}
	p1.debugValidate()
	return p1
}

func cloneCalls(origCalls []*Call, newargs map[*ResultArg]*ResultArg) []*Call {
	calls := make([]*Call, len(origCalls))
	for ci, c := range origCalls {
		c1 := new(Call)
		c1.Meta = c.Meta
		if c.Ret != nil {
			c1.Ret = clone(c.Ret, newargs).(*ResultArg)
		}
		c1.Args = make([]Arg, len(c.Args))
		for ai, arg := range c.Args {
			c1.Args[ai] = clone(arg, newargs)
		}
		c1.Props = c.Props
		calls[ci] = c1
	}
	return calls
}

func clone(arg Arg, newargs map[*ResultArg]*ResultArg) Arg {
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
		if a1.Res != nil {
			r := a1.Res
			if newargs != nil {
				r = newargs[a1.Res]
				a1.Res = r
			}
			if r.uses == nil {
				r.uses = make(map[*ResultArg]bool)
			}
			r.uses[a1] = true
		}
		a1.uses = nil // filled when we clone the referent
		if newargs != nil {
			newargs[a] = a1
		}
	default:
		panic(fmt.Sprintf("bad arg kind: %#v", arg))
	}
	return arg1
}
