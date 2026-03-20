// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"reflect"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
)

// Compare is a helper action that compares two string arguments for equality.
// The result of the comparison is written to the state under resultVar.
func Compare(arg1, arg2, resultVar string) Action {
	return &CompareAction{
		Arg1:      arg1,
		Arg2:      arg2,
		ResultVar: resultVar,
	}
}

// CompareAction performs the comparison. It is exported so tools can use its Run method.
type CompareAction struct {
	Arg1      string
	Arg2      string
	ResultVar string
}

func (a *CompareAction) Run(ctx *Context, v1, v2 string) (bool, error) {
	span := &trajectory.Span{
		Type: trajectory.SpanAction,
		Name: "compare",
	}
	if err := ctx.startSpan(span); err != nil {
		return false, err
	}

	res := v1 == v2

	span.Results = map[string]any{"result": res}
	return res, ctx.finishSpan(span, nil)
}

func (a *CompareAction) execute(ctx *Context) error {
	v1, ok := ctx.state[a.Arg1].(string)
	if !ok {
		return fmt.Errorf("compare missing string argument %q", a.Arg1)
	}
	v2, ok := ctx.state[a.Arg2].(string)
	if !ok {
		return fmt.Errorf("compare missing string argument %q", a.Arg2)
	}

	res, err := a.Run(ctx, v1, v2)
	if err != nil {
		return err
	}

	ctx.state[a.ResultVar] = res
	return nil
}

func (a *CompareAction) verify(ctx *verifyContext) {
	ctx.requireNotEmpty("compare", "Arg1", a.Arg1)
	ctx.requireNotEmpty("compare", "Arg2", a.Arg2)
	ctx.requireNotEmpty("compare", "ResultVar", a.ResultVar)

	ctx.requireInput("compare", a.Arg1, reflect.TypeFor[string]())
	ctx.requireInput("compare", a.Arg2, reflect.TypeFor[string]())
	ctx.provideOutput("compare", a.ResultVar, reflect.TypeFor[bool]())
}
