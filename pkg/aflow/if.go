// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"maps"
	"reflect"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
)

// If conditionally executes an action.
type If struct {
	Condition string
	Do        Action
	Else      Action

	ifVars map[string]reflect.Type
}

func (i *If) execute(ctx *Context) error {
	val, ok := ctx.state[i.Condition]
	if !ok {
		return fmt.Errorf("if condition %q is missing", i.Condition)
	}

	run := false
	if val != nil {
		v := reflect.ValueOf(val)
		if !v.IsZero() {
			run = true
			switch v.Kind() {
			case reflect.Slice, reflect.Map, reflect.Array, reflect.Chan:
				run = v.Len() > 0
			}
		}
	}

	span := &trajectory.Span{
		Type: trajectory.SpanAction,
		Name: "If",
		Args: map[string]any{i.Condition: val},
	}
	if err := ctx.startSpan(span); err != nil {
		return err
	}

	var err error
	if run {
		err = i.Do.execute(ctx)
	} else if i.Else != nil {
		err = i.Else.execute(ctx)
	}

	if err == nil {
		for name, typ := range i.ifVars {
			if _, ok := ctx.state[name]; !ok {
				ctx.state[name] = reflect.Zero(typ).Interface()
			}
		}
	}
	return ctx.finishSpan(span, err)
}

func (i *If) verify(ctx *verifyContext) {
	name := "If " + i.Condition
	if ctx.inputs {
		ctx.requireNotEmpty(name, "Condition", i.Condition)

		state := ctx.state[i.Condition]
		if state == nil {
			ctx.errorf(name, "no input %v", i.Condition)
		} else {
			state.used = true
			ctx.edges = append(ctx.edges, DataEdge{
				From: state.action,
				To:   name,
				Var:  i.Condition,
			})
		}
	}

	if ctx.outputs {
		i.verifyOutputs(ctx)
	} else {
		i.Do.verify(ctx)
		if i.Else != nil {
			i.Else.verify(ctx)
		}
	}
}

func (i *If) info() *ActionNode {
	n := &ActionNode{
		Type: "If",
		Name: "If " + i.Condition,
	}
	if i.Do != nil {
		do := i.Do.info()
		do.Branch = "Body"
		n.Children = append(n.Children, do)
	}
	if i.Else != nil {
		el := i.Else.info()
		el.Branch = "Else"
		n.Children = append(n.Children, el)
	}
	return n
}

func (i *If) verifyOutputs(ctx *verifyContext) {
	name := "If " + i.Condition
	origState := maps.Clone(ctx.state)
	i.Do.verify(ctx)
	doState := ctx.state

	ctx.state = maps.Clone(origState)
	if i.Else != nil {
		i.Else.verify(ctx)
	}

	i.ifVars = make(map[string]reflect.Type)
	for stateName, desc := range ctx.state {
		if origState[stateName] == nil {
			if doState[stateName] == nil {
				ctx.errorf(name, "output %v is produced by Else but not by Do", stateName)
			}
			i.ifVars[stateName] = desc.typ
		}
	}
	for stateName, desc := range doState {
		if origState[stateName] == nil {
			if existing := ctx.state[stateName]; existing != nil {
				if existing.typ != desc.typ {
					ctx.errorf(name, "output %v has different types in Do and Else", stateName)
				}
			} else {
				ctx.state[stateName] = desc
			}
			i.ifVars[stateName] = desc.typ
		}
	}
}
