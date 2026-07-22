// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"reflect"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
)

// Try representing "try { Do } catch { Catch }" action.
type Try struct {
	Do       Action
	Catch    Action
	ErrorVar string
}

func (t *Try) execute(ctx *Context) error {
	span := &trajectory.Span{
		Type: trajectory.SpanAction,
		Name: "try",
	}
	if err := ctx.startSpan(span); err != nil {
		return err
	}

	err := t.Do.execute(ctx)
	if err != nil {
		if t.ErrorVar != "" {
			ctx.state[t.ErrorVar] = err.Error()
		}
		var catchErr error
		if t.Catch != nil {
			catchErr = t.Catch.execute(ctx)
		}
		return ctx.finishSpan(span, catchErr)
	}

	if t.ErrorVar != "" {
		ctx.state[t.ErrorVar] = ""
	}
	return ctx.finishSpan(span, nil)
}

func (t *Try) verify(ctx *verifyContext) {
	t.Do.verify(ctx)
	if t.Catch != nil {
		t.Catch.verify(ctx)
	}
	if t.ErrorVar != "" {
		ctx.state[t.ErrorVar] = &varState{
			action: "try output",
			typ:    reflect.TypeFor[string](),
		}
	}
}
