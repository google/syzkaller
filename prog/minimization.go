// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

// Minimize minimizes program p into an equivalent program using the equivalence
// predicate pred.  It iteratively generates simpler programs and asks pred
// whether it is equal to the orginal program or not. If it is equivalent then
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

	var triedPaths map[string]bool

	var rec func(p *Prog, call *Call, arg Arg, path string) bool
	rec = func(p *Prog, call *Call, arg Arg, path string) bool {
		path += fmt.Sprintf("-%v", arg.Type().FieldName())
		switch typ := arg.Type().(type) {
		case *StructType:
			a := arg.(*GroupArg)
			for _, innerArg := range a.Inner {
				if rec(p, call, innerArg, path) {
					return true
				}
			}
		case *UnionType:
			a := arg.(*UnionArg)
			if rec(p, call, a.Option, path) {
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
				return rec(p, call, a.Res, path)
			}
		case *ArrayType:
			a := arg.(*GroupArg)
			for i, innerArg := range a.Inner {
				innerPath := fmt.Sprintf("%v-%v", path, i)
				if !triedPaths[innerPath] && !crash {
					if (typ.Kind == ArrayRangeLen && len(a.Inner) > int(typ.RangeBegin)) ||
						(typ.Kind == ArrayRandLen) {
						copy(a.Inner[i:], a.Inner[i+1:])
						a.Inner = a.Inner[:len(a.Inner)-1]
						removeArg(innerArg)
						p.Target.assignSizesCall(call)

						if pred(p, callIndex0) {
							p0 = p
						} else {
							triedPaths[innerPath] = true
						}

						return true
					}
				}
				if rec(p, call, innerArg, innerPath) {
					return true
				}
			}
		case *IntType, *FlagsType, *ProcType:
			// TODO: try to reset bits in ints
			// TODO: try to set separate flags
			if crash {
				return false
			}
			if triedPaths[path] {
				return false
			}
			triedPaths[path] = true
			a := arg.(*ConstArg)
			if a.Val == typ.Default() {
				return false
			}
			v0 := a.Val
			a.Val = typ.Default()
			if pred(p, callIndex0) {
				p0 = p
				return true
			} else {
				a.Val = v0
			}
		case *ResourceType:
			if crash {
				return false
			}
			if triedPaths[path] {
				return false
			}
			triedPaths[path] = true
			a := arg.(*ResultArg)
			if a.Res == nil {
				return false
			}
			r0 := a.Res
			a.Res = nil
			a.Val = typ.Default()
			if pred(p, callIndex0) {
				p0 = p
				return true
			} else {
				a.Res = r0
				a.Val = 0
			}
		case *BufferType:
			// TODO: try to set individual bytes to 0
			if triedPaths[path] {
				return false
			}
			triedPaths[path] = true
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
					if pred(p, callIndex0) {
						continue
					}
					a.data = a.Data()[:len(a.Data())+step]
					p.Target.assignSizesCall(call)
				}
				step /= 2
				if crash {
					break
				}
			}
			p0 = p
		case *VmaType, *LenType, *CsumType, *ConstType:
			// TODO: try to remove offset from vma
			return false
		default:
			panic(fmt.Sprintf("unknown arg type '%+v'", typ))
		}
		return false
	}

	// Try to minimize individual args.
	for i := 0; i < len(p0.Calls); i++ {
		triedPaths = make(map[string]bool)
	again:
		p := p0.Clone()
		call := p.Calls[i]
		for j, arg := range call.Args {
			if rec(p, call, arg, fmt.Sprintf("%v", j)) {
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
