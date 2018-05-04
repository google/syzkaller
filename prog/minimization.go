// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

// Minimize minimizes program p into an equivalent program using the equivalence
// predicate pred.  It iteratively generates simpler programs and asks pred
// whether it is equal to the original program or not. If it is equivalent then
// the simplification attempt is committed and the process continues.
func Minimize(p0 *Prog, callIndex0 int, crash bool, pred0 func(*Prog, int) bool) (*Prog, int) {
	pred := pred0
	if debug {
		pred = func(p *Prog, callIndex int) bool {
			if err := p.validate(); err != nil {
				panic(err)
			}
			return pred0(p, callIndex)
		}
	}
	name0 := ""
	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(p0.Calls) {
			panic("bad call index")
		}
		name0 = p0.Calls[callIndex0].Meta.Name
	}

	// Try to remove all calls except the last one one-by-one.
	p0, callIndex0 = removeCalls(p0, callIndex0, crash, pred)

	// Try to minimize individual args.
	for i := 0; i < len(p0.Calls); i++ {
		ctx := &minimizeArgsCtx{
			p0:         &p0,
			callIndex0: callIndex0,
			crash:      crash,
			pred:       pred,
			triedPaths: make(map[string]bool),
		}
	again:
		p := p0.Clone()
		call := p.Calls[i]
		for j, arg := range call.Args {
			if ctx.do(p, call, arg, fmt.Sprintf("%v", j)) {
				goto again
			}
		}
	}

	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(p0.Calls) || name0 != p0.Calls[callIndex0].Meta.Name {
			panic(fmt.Sprintf("bad call index after minimization: ncalls=%v index=%v call=%v/%v",
				len(p0.Calls), callIndex0, name0, p0.Calls[callIndex0].Meta.Name))
		}
	}
	return p0, callIndex0
}

func removeCalls(p0 *Prog, callIndex0 int, crash bool, pred func(*Prog, int) bool) (*Prog, int) {
	for i := len(p0.Calls) - 1; i >= 0; i-- {
		if i == callIndex0 {
			continue
		}
		callIndex := callIndex0
		if i < callIndex {
			callIndex--
		}
		p := p0.Clone()
		p.removeCall(i)
		if !pred(p, callIndex) {
			continue
		}
		p0 = p
		callIndex0 = callIndex
	}
	return p0, callIndex0
}

type minimizeArgsCtx struct {
	p0         **Prog
	callIndex0 int
	crash      bool
	pred       func(*Prog, int) bool
	triedPaths map[string]bool
}

func (ctx *minimizeArgsCtx) do(p *Prog, call *Call, arg Arg, path string) bool {
	path += fmt.Sprintf("-%v", arg.Type().FieldName())
	switch typ := arg.Type().(type) {
	case *StructType:
		a := arg.(*GroupArg)
		for _, innerArg := range a.Inner {
			if ctx.do(p, call, innerArg, path) {
				return true
			}
		}
	case *UnionType:
		a := arg.(*UnionArg)
		if ctx.do(p, call, a.Option, path) {
			return true
		}
	case *PtrType:
		// TODO: try to remove optional ptrs
		a, ok := arg.(*PointerArg)
		if !ok {
			// Can also be *ConstArg.
			return false
		}
		if a.Res != nil {
			return ctx.do(p, call, a.Res, path)
		}
	case *ArrayType:
		a := arg.(*GroupArg)
		for i, innerArg := range a.Inner {
			innerPath := fmt.Sprintf("%v-%v", path, i)
			if !ctx.triedPaths[innerPath] && !ctx.crash {
				if (typ.Kind == ArrayRangeLen && len(a.Inner) > int(typ.RangeBegin)) ||
					(typ.Kind == ArrayRandLen) {
					copy(a.Inner[i:], a.Inner[i+1:])
					a.Inner = a.Inner[:len(a.Inner)-1]
					removeArg(innerArg)
					p.Target.assignSizesCall(call)

					if ctx.pred(p, ctx.callIndex0) {
						*ctx.p0 = p
					} else {
						ctx.triedPaths[innerPath] = true
					}
					return true
				}
			}
			if ctx.do(p, call, innerArg, innerPath) {
				return true
			}
		}
	case *IntType, *FlagsType, *ProcType:
		// TODO: try to reset bits in ints
		// TODO: try to set separate flags
		if ctx.crash || ctx.triedPaths[path] {
			return false
		}
		ctx.triedPaths[path] = true
		a := arg.(*ConstArg)
		if a.Val == typ.Default() {
			return false
		}
		v0 := a.Val
		a.Val = typ.Default()
		if ctx.pred(p, ctx.callIndex0) {
			*ctx.p0 = p
			return true
		}
		a.Val = v0
	case *ResourceType:
		if ctx.crash || ctx.triedPaths[path] {
			return false
		}
		ctx.triedPaths[path] = true
		a := arg.(*ResultArg)
		if a.Res == nil {
			return false
		}
		r0 := a.Res
		a.Res = nil
		a.Val = typ.Default()
		if ctx.pred(p, ctx.callIndex0) {
			*ctx.p0 = p
			return true
		}
		a.Res = r0
		a.Val = 0
	case *BufferType:
		// TODO: try to set individual bytes to 0
		if ctx.triedPaths[path] {
			return false
		}
		ctx.triedPaths[path] = true
		if typ.Kind != BufferBlobRand && typ.Kind != BufferBlobRange ||
			typ.Dir() == DirOut {
			return false
		}
		a := arg.(*DataArg)
		minLen := int(typ.RangeBegin)
		for step := len(a.Data()) - minLen; len(a.Data()) > minLen && step > 0; {
			if len(a.Data())-step >= minLen {
				a.data = a.Data()[:len(a.Data())-step]
				p.Target.assignSizesCall(call)
				if ctx.pred(p, ctx.callIndex0) {
					continue
				}
				a.data = a.Data()[:len(a.Data())+step]
				p.Target.assignSizesCall(call)
			}
			step /= 2
			if ctx.crash {
				break
			}
		}
		*ctx.p0 = p
	case *VmaType, *LenType, *CsumType, *ConstType:
		return false
	default:
		panic(fmt.Sprintf("unknown arg type '%+v'", typ))
	}
	return false
}
