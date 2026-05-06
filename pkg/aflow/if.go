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

	ifVars map[string]reflect.Type
}

func (i *If) execute(ctx *Context) error {
	val, ok := ctx.state[i.Condition]
	if !ok {
		return fmt.Errorf("if condition %q is missing", i.Condition)
	}

	run := val != nil && !reflect.ValueOf(val).IsZero()
	if run {
		span := &trajectory.Span{
			Type: trajectory.SpanAction,
			Name: "If",
			Args: map[string]any{i.Condition: val},
		}
		if err := ctx.startSpan(span); err != nil {
			return err
		}
		err := i.Do.execute(ctx)
		if err := ctx.finishSpan(span, err); err != nil {
			return err
		}
	} else {
		// If the condition is false, populate outputs with zero values
		// so that subsequent actions or the final output extraction don't panic.
		for name, typ := range i.ifVars {
			if _, ok := ctx.state[name]; !ok {
				ctx.state[name] = reflect.Zero(typ).Interface()
			}
		}
	}
	return nil
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
		origState := maps.Clone(ctx.state)
		i.Do.verify(ctx)
		i.ifVars = make(map[string]reflect.Type)
		for name, desc := range ctx.state {
			if origState[name] == nil {
				i.ifVars[name] = desc.typ
			}
		}
	} else {
		i.Do.verify(ctx)
	}
}
