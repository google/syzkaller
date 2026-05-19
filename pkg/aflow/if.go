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
	if ctx.inputs {
		ctx.requireNotEmpty("If", "Condition", i.Condition)

		state := ctx.state[i.Condition]
		if state == nil {
			ctx.errorf("If", "no input %v", i.Condition)
		} else {
			state.used = true
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

func (i *If) verifyOutputs(ctx *verifyContext) {
	origState := maps.Clone(ctx.state)
	i.Do.verify(ctx)
	doState := ctx.state

	ctx.state = maps.Clone(origState)
	if i.Else != nil {
		i.Else.verify(ctx)
	}

	i.ifVars = make(map[string]reflect.Type)
	for name, desc := range ctx.state {
		if origState[name] == nil {
			if doState[name] == nil {
				ctx.errorf("If", "output %v is produced by Else but not by Do", name)
			}
			i.ifVars[name] = desc.typ
		}
	}
	for name, desc := range doState {
		if origState[name] == nil {
			if existing := ctx.state[name]; existing != nil {
				if existing.typ != desc.typ {
					ctx.errorf("If", "output %v has different types in Do and Else", name)
				}
			} else {
				ctx.state[name] = desc
			}
			i.ifVars[name] = desc.typ
		}
	}
}
