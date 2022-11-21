// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"reflect"
)

// Minimize minimizes program p into an equivalent program using the equivalence
// predicate pred. It iteratively generates simpler programs and asks pred
// whether it is equal to the original program or not. If it is equivalent then
// the simplification attempt is committed and the process continues.
func Minimize(p0 *Prog, callIndex0 int, crash bool, pred0 func(*Prog, int) bool) (*Prog, int) {
	pred := func(p *Prog, callIndex int) bool {
		p.sanitizeFix()
		p.debugValidate()
		return pred0(p, callIndex)
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

	// Try to reset all call props to their default values.
	p0 = resetCallProps(p0, callIndex0, pred)

	// Try to minimize individual calls.
	for i := 0; i < len(p0.Calls); i++ {
		if p0.Calls[i].Meta.Attrs.NoMinimize {
			continue
		}
		ctx := &minimizeArgsCtx{
			target:     p0.Target,
			p0:         &p0,
			callIndex0: callIndex0,
			crash:      crash,
			pred:       pred,
			triedPaths: make(map[string]bool),
		}
	again:
		ctx.p = p0.Clone()
		ctx.call = ctx.p.Calls[i]
		for j, field := range ctx.call.Meta.Args {
			if ctx.do(ctx.call.Args[j], field.Name, "") {
				goto again
			}
		}
		p0 = minimizeCallProps(p0, i, callIndex0, pred)
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
		p.RemoveCall(i)
		if !pred(p, callIndex) {
			continue
		}
		p0 = p
		callIndex0 = callIndex
	}
	return p0, callIndex0
}

func resetCallProps(p0 *Prog, callIndex0 int, pred func(*Prog, int) bool) *Prog {
	// Try to reset all call props to their default values.
	// This should be reasonable for many progs.
	p := p0.Clone()
	anyDifferent := false
	for idx := range p.Calls {
		if !reflect.DeepEqual(p.Calls[idx].Props, CallProps{}) {
			p.Calls[idx].Props = CallProps{}
			anyDifferent = true
		}
	}
	if anyDifferent && pred(p, callIndex0) {
		return p
	}
	return p0
}

func minimizeCallProps(p0 *Prog, callIndex, callIndex0 int, pred func(*Prog, int) bool) *Prog {
	props := p0.Calls[callIndex].Props

	// Try to drop fault injection.
	if props.FailNth > 0 {
		p := p0.Clone()
		p.Calls[callIndex].Props.FailNth = 0
		if pred(p, callIndex0) {
			p0 = p
		}
	}

	// Try to drop async.
	if props.Async {
		p := p0.Clone()
		p.Calls[callIndex].Props.Async = false
		if pred(p, callIndex0) {
			p0 = p
		}
	}

	// Try to drop rerun.
	if props.Rerun > 0 {
		p := p0.Clone()
		p.Calls[callIndex].Props.Rerun = 0
		if pred(p, callIndex0) {
			p0 = p
		}
	}

	return p0
}

type minimizeArgsCtx struct {
	target     *Target
	p0         **Prog
	p          *Prog
	call       *Call
	callIndex0 int
	crash      bool
	pred       func(*Prog, int) bool
	triedPaths map[string]bool
}

func (ctx *minimizeArgsCtx) do(arg Arg, field, path string) bool {
	path += fmt.Sprintf("-%v", field)
	if ctx.triedPaths[path] {
		return false
	}
	p0 := *ctx.p0
	if arg.Type().minimize(ctx, arg, path) {
		return true
	}
	if *ctx.p0 == ctx.p {
		// If minimize committed a new program, it must return true.
		// Otherwise *ctx.p0 and ctx.p will point to the same program
		// and any temp mutations to ctx.p will unintentionally affect ctx.p0.
		panic("shared program committed")
	}
	if *ctx.p0 != p0 {
		// New program was committed, but we did not start iteration anew.
		// This means we are iterating over a stale tree and any changes won't be visible.
		panic("iterating over stale program")
	}
	ctx.triedPaths[path] = true
	return false
}

func (typ *TypeCommon) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return false
}

func (typ *StructType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*GroupArg)
	for i, innerArg := range a.Inner {
		if ctx.do(innerArg, typ.Fields[i].Name, path) {
			return true
		}
	}
	return false
}

func (typ *UnionType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*UnionArg)
	return ctx.do(a.Option, typ.Fields[a.Index].Name, path)
}

func (typ *PtrType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*PointerArg)
	if a.Res == nil {
		return false
	}
	if path1 := path + ">"; !ctx.triedPaths[path1] {
		removeArg(a.Res)
		replaceArg(a, MakeSpecialPointerArg(a.Type(), a.Dir(), 0))
		ctx.target.assignSizesCall(ctx.call)
		if ctx.pred(ctx.p, ctx.callIndex0) {
			*ctx.p0 = ctx.p
		}
		ctx.triedPaths[path1] = true
		return true
	}
	return ctx.do(a.Res, "", path)
}

func (typ *ArrayType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*GroupArg)
	for i := len(a.Inner) - 1; i >= 0; i-- {
		elem := a.Inner[i]
		elemPath := fmt.Sprintf("%v-%v", path, i)
		// Try to remove individual elements one-by-one.
		if !ctx.crash && !ctx.triedPaths[elemPath] &&
			(typ.Kind == ArrayRandLen ||
				typ.Kind == ArrayRangeLen && uint64(len(a.Inner)) > typ.RangeBegin) {
			ctx.triedPaths[elemPath] = true
			copy(a.Inner[i:], a.Inner[i+1:])
			a.Inner = a.Inner[:len(a.Inner)-1]
			removeArg(elem)
			ctx.target.assignSizesCall(ctx.call)
			if ctx.pred(ctx.p, ctx.callIndex0) {
				*ctx.p0 = ctx.p
			}
			return true
		}
		if ctx.do(elem, "", elemPath) {
			return true
		}
	}
	return false
}

func (typ *IntType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return minimizeInt(ctx, arg, path)
}

func (typ *FlagsType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return minimizeInt(ctx, arg, path)
}

func (typ *ProcType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if !typ.Optional() {
		// Default value for ProcType is 0 (same for all PID's).
		// Usually 0 either does not make sense at all or make different PIDs collide
		// (since we use ProcType to separate value ranges for different PIDs).
		// So don't change ProcType to 0 unless the type is explicitly marked as opt
		// (in that case we will also generate 0 anyway).
		return false
	}
	return minimizeInt(ctx, arg, path)
}

func minimizeInt(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	// TODO: try to reset bits in ints
	// TODO: try to set separate flags
	if ctx.crash {
		return false
	}
	a := arg.(*ConstArg)
	def := arg.Type().DefaultArg(arg.Dir()).(*ConstArg)
	if a.Val == def.Val {
		return false
	}
	v0 := a.Val
	a.Val = def.Val
	if ctx.pred(ctx.p, ctx.callIndex0) {
		*ctx.p0 = ctx.p
		ctx.triedPaths[path] = true
		return true
	}
	a.Val = v0
	return false
}

func (typ *ResourceType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if ctx.crash {
		return false
	}
	a := arg.(*ResultArg)
	if a.Res == nil {
		return false
	}
	r0 := a.Res
	delete(a.Res.uses, a)
	a.Res, a.Val = nil, typ.Default()
	if ctx.pred(ctx.p, ctx.callIndex0) {
		*ctx.p0 = ctx.p
	} else {
		a.Res, a.Val = r0, 0
		a.Res.uses[a] = true
	}
	ctx.triedPaths[path] = true
	return true
}

func (typ *BufferType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if arg.Dir() == DirOut {
		return false
	}
	if typ.IsCompressed() {
		panic(fmt.Sprintf("minimizing `no_minimize` call %v", ctx.call.Meta.Name))
	}
	a := arg.(*DataArg)
	switch typ.Kind {
	case BufferBlobRand, BufferBlobRange:
		// TODO: try to set individual bytes to 0
		len0 := len(a.Data())
		minLen := int(typ.RangeBegin)
		for step := len(a.Data()) - minLen; len(a.Data()) > minLen && step > 0; {
			if len(a.Data())-step >= minLen {
				a.data = a.Data()[:len(a.Data())-step]
				ctx.target.assignSizesCall(ctx.call)
				if ctx.pred(ctx.p, ctx.callIndex0) {
					continue
				}
				a.data = a.Data()[:len(a.Data())+step]
				ctx.target.assignSizesCall(ctx.call)
			}
			step /= 2
			if ctx.crash {
				break
			}
		}
		if len(a.Data()) != len0 {
			*ctx.p0 = ctx.p
			ctx.triedPaths[path] = true
			return true
		}
	case BufferFilename:
		// Try to undo target.SpecialFileLenghts mutation
		// and reduce file name length.
		if !typ.Varlen() {
			return false
		}
		data0 := append([]byte{}, a.Data()...)
		a.data = bytes.TrimRight(a.Data(), specialFileLenPad+"\x00")
		if !typ.NoZ {
			a.data = append(a.data, 0)
		}
		if bytes.Equal(a.data, data0) {
			return false
		}
		ctx.target.assignSizesCall(ctx.call)
		if ctx.pred(ctx.p, ctx.callIndex0) {
			*ctx.p0 = ctx.p
		}
		ctx.triedPaths[path] = true
		return true
	}
	return false
}
