// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"maps"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
)

func NewFuncAction[Args, Results any](name string, fn func(*Context, Args) (Results, error)) Action {
	return &funcAction[Args, Results]{
		name: name,
		fn:   fn,
	}
}

type funcAction[Args, Results any] struct {
	name string
	fn   func(*Context, Args) (Results, error)
}

func (a *funcAction[Args, Results]) execute(ctx *Context) error {
	args, err := convertFromMap[Args](ctx.state, false, false)
	if err != nil {
		return err
	}
	span := &trajectory.Span{
		Type: trajectory.SpanAction,
		Name: a.name,
	}
	if err := ctx.startSpan(span); err != nil {
		return err
	}
	res, fnErr := a.fn(ctx, args)
	span.Results = convertToMap(res)
	maps.Insert(ctx.state, maps.All(span.Results))
	return ctx.finishSpan(span, fnErr)
}

func (a *funcAction[Args, Results]) verify(ctx *verifyContext) {
	ctx.requireNotEmpty(a.name, "Name", a.name)
	requireInputs[Args](ctx, a.name)
	provideOutputs[Results](ctx, a.name)
}
