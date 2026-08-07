// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"reflect"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
)

// Try represents a "try { Do } catch { Catch }" action.
// It only catches BadCallError (e.g. judge stopping execution or recoverable LLM errors)
// from Do and executes Catch. Fatal errors (e.g. FlowError, token limit overflows,
// or infrastructure failures) are not caught and will propagate up.
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
		// Fatal errors (e.g. flow errors, token limit overflows, or infrastructure failures)
		// are not caught and should propagate up to fail/stop the workflow.
		if !IsBadCallError(err) {
			return ctx.finishSpan(span, err)
		}
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
