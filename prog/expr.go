// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"errors"
	"fmt"
)

func (bo BinaryExpression) Evaluate(finder ArgFinder) (uint64, bool) {
	left, ok := bo.Left.Evaluate(finder)
	if !ok {
		return 0, false
	}
	right, ok := bo.Right.Evaluate(finder)
	if !ok {
		return 0, false
	}
	switch bo.Operator {
	case OperatorCompareEq:
		if left == right {
			return 1, true
		}
		return 0, true
	case OperatorCompareNeq:
		if left != right {
			return 1, true
		}
		return 0, true
	case OperatorBinaryAnd:
		return left & right, true
	case OperatorOr:
		if left != 0 || right != 0 {
			return 1, true
		}
		return 0, true
	}
	panic(fmt.Sprintf("unknown operator %q", bo.Operator))
}

func (v *Value) Evaluate(finder ArgFinder) (uint64, bool) {
	if len(v.Path) == 0 {
		return v.Value, true
	}
	found := finder(v.Path)
	if found == SquashedArgFound {
		// This is expectable.
		return 0, false
	}
	if found == nil {
		panic(fmt.Sprintf("no argument was found by %v", v.Path))
	}
	constArg, ok := found.(*ConstArg)
	if !ok {
		panic("value expressions must only rely on int fields")
	}
	return constArg.Val, true
}

func makeArgFinder(t *Target, c *Call, unionArg *UnionArg, parents parentStack) ArgFinder {
	return func(path []string) Arg {
		f := t.findArg(unionArg.Option, path, nil, nil, parents, 0)
		if f == nil {
			return nil
		}
		if f.isAnyPtr {
			return SquashedArgFound
		}
		return f.arg
	}
}

func (r *randGen) patchConditionalFields(c *Call, s *state) (extra []*Call, changed bool) {
	if r.patchConditionalDepth > 1 && !r.EnforceDeps {
		// Some nested patchConditionalFields() calls are fine as we could trigger a resource
		// constructor via generateArg(). But since nested createResource() calls are prohibited,
		// patchConditionalFields() should never be nested more than 2 times.
		panic("third nested patchConditionalFields call")
	}
	r.patchConditionalDepth++
	defer func() { r.patchConditionalDepth-- }()

	var extraCalls []*Call
	var anyPatched bool
	for {
		replace := map[Arg]Arg{}
		forEachStaleUnion(r.target, c,
			func(unionArg *UnionArg, unionType *UnionType, okIndices []int) {
				idx := okIndices[r.Intn(len(okIndices))]
				newType, newDir := unionType.Fields[idx].Type,
					unionType.Fields[idx].Dir(unionArg.Dir())
				newTypeArg, newCalls := r.generateArg(s, newType, newDir)
				replace[unionArg] = MakeUnionArg(unionType, newDir, newTypeArg, idx)
				extraCalls = append(extraCalls, newCalls...)
				anyPatched = true
			})
		for old, new := range replace {
			replaceArg(old, new)
		}
		// The newly inserted argument might contain more arguments we need
		// to patch.
		// Repeat until we have to change nothing.
		if len(replace) == 0 {
			break
		}
	}
	return extraCalls, anyPatched
}

func forEachStaleUnion(target *Target, c *Call, cb func(*UnionArg, *UnionType, []int)) {
	for _, callArg := range c.Args {
		foreachSubArgWithStack(callArg, func(arg Arg, argCtx *ArgCtx) {
			if target.isAnyPtr(arg.Type()) {
				argCtx.Stop = true
				return
			}
			unionArg, ok := arg.(*UnionArg)
			if !ok {
				return
			}
			unionType, ok := arg.Type().(*UnionType)
			if !ok || !unionType.isConditional() {
				return
			}
			argFinder := makeArgFinder(target, c, unionArg, argCtx.parentStack)
			ok, calculated := checkUnionArg(unionArg.Index, unionType, argFinder)
			if !calculated {
				// Let it stay as is.
				return
			}
			if !unionArg.transient && ok {
				return
			}
			matchingIndices := matchingUnionArgs(unionType, argFinder)
			if len(matchingIndices) == 0 {
				// Conditional fields are transformed in such a way
				// that one field always matches.
				// For unions we demand that there's a field w/o conditions.
				panic(fmt.Sprintf("no matching union fields: %#v", unionType))
			}
			cb(unionArg, unionType, matchingIndices)
		})
	}
}

func checkUnionArg(idx int, typ *UnionType, finder ArgFinder) (ok, calculated bool) {
	field := typ.Fields[idx]
	if field.Condition == nil {
		return true, true
	}
	val, ok := field.Condition.Evaluate(finder)
	if !ok {
		// We could not calculate the expression.
		// Let the union stay as it was.
		return true, false
	}
	return val != 0, true
}

func matchingUnionArgs(typ *UnionType, finder ArgFinder) []int {
	var ret []int
	for i := range typ.Fields {
		ok, _ := checkUnionArg(i, typ, finder)
		if ok {
			ret = append(ret, i)
		}
	}
	return ret
}

func (p *Prog) checkConditions() error {
	for _, c := range p.Calls {
		err := c.checkConditions(p.Target, false)
		if err != nil {
			return err
		}
	}
	return nil
}

var ErrViolatedConditions = errors.New("conditional fields rules violation")

func (c *Call) checkConditions(target *Target, ignoreTransient bool) error {
	var ret error
	forEachStaleUnion(target, c,
		func(a *UnionArg, t *UnionType, okIndices []int) {
			if ignoreTransient && a.transient {
				return
			}
			ret = fmt.Errorf("%w union %s field is #%d(%s), but %v satisfy conditions",
				ErrViolatedConditions, t.Name(), a.Index, t.Fields[a.Index].Name,
				okIndices)
		})
	return ret
}

func (c *Call) setDefaultConditions(target *Target, transientOnly bool) bool {
	var anyReplaced bool
	// Replace stale conditions with the default values of their correct types.
	for {
		replace := map[Arg]Arg{}
		forEachStaleUnion(target, c,
			func(unionArg *UnionArg, unionType *UnionType, okIndices []int) {
				if transientOnly && !unionArg.transient {
					return
				}
				idx := okIndices[0]
				if defIdx, ok := unionType.defaultField(); ok {
					// If there's a default value available, use it.
					idx = defIdx
				}
				field := unionType.Fields[idx]
				replace[unionArg] = MakeUnionArg(unionType,
					unionArg.Dir(),
					field.DefaultArg(field.Dir(unionArg.Dir())),
					idx)
			})
		for old, new := range replace {
			anyReplaced = true
			replaceArg(old, new)
		}
		if len(replace) == 0 {
			break
		}
	}
	return anyReplaced
}
