// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"maps"
	"reflect"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
)

// DoWhile represents "do { body } while (cond)" loop.
type DoWhile struct {
	// Dody of the loop.
	Do Action
	// Exit condition. It should be a string state variable.
	// The loop exists when the variable is empty.
	While string
	// Max interations for the loop.
	// Must be specified to avoid unintended effectively infinite loops.
	MaxIterations int

	loopVars map[string]reflect.Type
}

func (dw *DoWhile) execute(ctx *Context) error {
	span := &trajectory.Span{
		Type: trajectory.SpanLoop,
	}
	if err := ctx.startSpan(span); err != nil {
		return err
	}
	err := dw.loop(ctx)
	if err := ctx.finishSpan(span, err); err != nil {
		return err
	}
	return nil
}

func (dw *DoWhile) loop(ctx *Context) error {
	for name, typ := range dw.loopVars {
		if _, ok := ctx.state[name]; ok {
			return fmt.Errorf("loop var %q is already defined", name)
		}
		ctx.state[name] = reflect.Zero(typ).Interface()
	}
	for iter := 0; iter < dw.MaxIterations; iter++ {
		span := &trajectory.Span{
			Type: trajectory.SpanLoopIteration,
			Name: fmt.Sprint(iter),
		}
		if err := ctx.startSpan(span); err != nil {
			return err
		}
		err := dw.Do.execute(ctx)
		if err := ctx.finishSpan(span, err); err != nil {
			return err
		}
		if ctx.state[dw.While].(string) == "" {
			return nil
		}
	}
	return fmt.Errorf("DoWhile loop is going in cycles for %v iterations", dw.MaxIterations)
}

func (dw *DoWhile) verify(ctx *verifyContext) {
	if max := 1000; dw.MaxIterations <= 0 || dw.MaxIterations >= max {
		ctx.errorf("DoWhile", "bad MaxIterations value %v, should be within [1, %v]",
			dw.MaxIterations, max)
	}
	// Verification of loops is a bit tricky.
	// Normally we require each variable to be defined before use, but loops violate
	// the assumption. An action in a loop body may want to use a variable produced
	// by a subsequent action in the body on the previous iteration (otherwise there
	// is no way to provide feedback from one iteration to the next iteration).
	// But on the first iteration that variable is not defined yet. To resolve this,
	// we split verification into 2 parts: first, all body actions provide outputs,
	// and we collect all provided outputs in loopVars; second, we verify their inputs
	// (with all outputs from the whole body already defined). Later, during execution
	// we will define all loopVars to zero values before starting the loop body.
	inputs, outputs := ctx.inputs, ctx.outputs
	defer func() {
		ctx.inputs, ctx.outputs = inputs, outputs
	}()
	if outputs {
		ctx.inputs, ctx.outputs = false, true
		origState := maps.Clone(ctx.state)
		dw.Do.verify(ctx)
		dw.loopVars = make(map[string]reflect.Type)
		for name, desc := range ctx.state {
			if origState[name] == nil {
				dw.loopVars[name] = desc.typ
			}
		}
	}
	if inputs {
		ctx.inputs, ctx.outputs = true, false
		dw.Do.verify(ctx)
		ctx.requireNotEmpty("DoWhile", "While", dw.While)
		ctx.requireInput("DoWhile", dw.While, reflect.TypeFor[string]())
	}
}
