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
	// Body of the loop.
	Do Action
	// Exit condition. It should be a string or bool state variable.
	// The loop exits when the variable is empty or false.
	While string
	// Max iterations for the loop.
	// Must be specified to avoid unintended effectively infinite loops.
	MaxIterations int
	// MapOutputs renames or overrides variables produced inside the loop
	// before exposing them to the parent context upon loop completion.
	MapOutputs map[string]string
	// OnMaxIterations is executed when the loop reaches MaxIterations instead
	// of returning an error. It executes after the loop finishes and MapOutputs
	// has been applied; its outputs are not mapped by MapOutputs.
	OnMaxIterations Action

	loopVars map[string]reflect.Type
}

func (dw *DoWhile) execute(ctx *Context) error {
	span := &trajectory.Span{
		Type: trajectory.SpanLoop,
	}
	if err := ctx.startSpan(span); err != nil {
		return err
	}
	exhausted, err := dw.loop(ctx)
	if err := ctx.finishSpan(span, err); err != nil {
		return err
	}
	if exhausted && dw.OnMaxIterations != nil {
		return dw.OnMaxIterations.execute(ctx)
	}
	return nil
}

func (dw *DoWhile) loop(ctx *Context) (bool, error) {
	for name, typ := range dw.loopVars {
		// We allow redefinition of loop variables to support nested loops.
		// They are reset to zero values at the start of the loop.
		ctx.state[name] = reflect.Zero(typ).Interface()
	}
	for iter := range dw.MaxIterations {
		span := &trajectory.Span{
			Type: trajectory.SpanLoopIteration,
			Name: fmt.Sprint(iter),
		}
		if err := ctx.startSpan(span); err != nil {
			return false, err
		}
		err := dw.Do.execute(ctx)
		if err := ctx.finishSpan(span, err); err != nil {
			return false, err
		}
		val := ctx.state[dw.While]
		cond := false
		switch v := val.(type) {
		case string:
			cond = v != ""
		case bool:
			cond = v
		}
		if !cond {
			dw.mapOutputs(ctx)
			return false, nil
		}
	}
	if dw.OnMaxIterations != nil {
		dw.mapOutputs(ctx)
		return true, nil
	}
	return false, fmt.Errorf("DoWhile reached max iteration limit %v", dw.MaxIterations)
}

func (dw *DoWhile) mapOutputs(ctx *Context) {
	for from, to := range dw.MapOutputs {
		if val, ok := ctx.state[from]; ok {
			ctx.state[to] = val
		}
	}
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
		for from := range dw.MapOutputs {
			delete(ctx.state, from)
		}
		dw.Do.verify(ctx)
		dw.loopVars = make(map[string]reflect.Type)
		for name, desc := range ctx.state {
			if origState[name] == nil {
				dw.loopVars[name] = desc.typ
			}
		}
		maps.Copy(ctx.state, origState)
		for from, to := range dw.MapOutputs {
			desc := ctx.state[from]
			if desc == nil {
				ctx.errorf("DoWhile", "MapOutputs source %v is not produced in loop", from)
				continue
			}
			ctx.state[to] = &varState{
				action: "DoWhile",
				typ:    desc.typ,
			}
		}
		if dw.OnMaxIterations != nil {
			dw.verifyOnMaxIterations(ctx, origState)
		}
	}
	if inputs {
		ctx.inputs, ctx.outputs = true, false
		dw.Do.verify(ctx)
		ctx.requireNotEmpty("DoWhile", "While", dw.While)
		state := ctx.state[dw.While]
		if state == nil {
			ctx.errorf("DoWhile", "no input %v", dw.While)
		} else if state.typ.Kind() != reflect.String && state.typ.Kind() != reflect.Bool {
			ctx.errorf("DoWhile", "input %v has wrong type: want string or bool, has %v", dw.While, state.typ)
		} else {
			state.used = true
		}
		if dw.OnMaxIterations != nil {
			dw.OnMaxIterations.verify(ctx)
		}
	}
}

func (dw *DoWhile) verifyOnMaxIterations(ctx *verifyContext, origState map[string]*varState) {
	loopState := ctx.state
	ctx.state = maps.Clone(origState)
	dw.OnMaxIterations.verify(ctx)
	for name, desc := range ctx.state {
		if origState[name] != nil {
			continue
		}
		expected := loopState[name]
		if expected == nil {
			ctx.errorf("DoWhile", "output %v is produced by OnMaxIterations but not by Do", name)
			continue
		}
		if expected.typ != desc.typ {
			ctx.errorf("DoWhile", "output %v has different types in Do and OnMaxIterations: want %v, has %v",
				name, expected.typ, desc.typ)
		}
	}
	ctx.state = loopState
}

// ForEach executes an action for each element in a slice.
type ForEach struct {
	// List is the name of the state variable containing the slice.
	List string
	// Item is the name of the state variable to inject the current element into.
	Item string
	// Do is the action to execute for each item.
	Do Action

	loopVars map[string]reflect.Type
}

func (f *ForEach) execute(ctx *Context) error {
	val, ok := ctx.state[f.List]
	if !ok {
		return fmt.Errorf("ForEach list %q is missing", f.List)
	}

	rv := reflect.ValueOf(val)
	if rv.Kind() != reflect.Slice {
		return fmt.Errorf("ForEach list %q is not a slice", f.List)
	}

	span := &trajectory.Span{
		Type: trajectory.SpanLoop,
		Name: "ForEach",
	}
	if err := ctx.startSpan(span); err != nil {
		return err
	}

	for name, typ := range f.loopVars {
		if _, ok := ctx.state[name]; ok {
			return fmt.Errorf("loop var %q is already defined", name)
		}
		ctx.state[name] = reflect.Zero(typ).Interface()
	}

	for i := range rv.Len() {
		itemVal := rv.Index(i).Interface()

		iterSpan := &trajectory.Span{
			Type: trajectory.SpanLoopIteration,
			Name: fmt.Sprintf("%d", i),
		}
		if err := ctx.startSpan(iterSpan); err != nil {
			return err
		}

		ctx.state[f.Item] = itemVal

		err := f.Do.execute(ctx)
		if err := ctx.finishSpan(iterSpan, err); err != nil {
			return ctx.finishSpan(span, err)
		}
	}

	delete(ctx.state, f.Item)
	return ctx.finishSpan(span, nil)
}

func (f *ForEach) verify(ctx *verifyContext) {
	ctx.requireNotEmpty("ForEach", "List", f.List)
	ctx.requireNotEmpty("ForEach", "Item", f.Item)

	state := ctx.state[f.List]
	if ctx.inputs {
		if state == nil {
			ctx.errorf("ForEach", "no input %v", f.List)
		} else if state.typ.Kind() != reflect.Slice {
			ctx.errorf("ForEach", "input %v has wrong type: want slice, has %v", f.List, state.typ)
		} else {
			state.used = true
		}
	}

	var elemType reflect.Type
	if state != nil && state.typ.Kind() == reflect.Slice {
		elemType = state.typ.Elem()
	} else {
		elemType = reflect.TypeFor[any]()
	}

	inputs, outputs := ctx.inputs, ctx.outputs
	defer func() {
		ctx.inputs, ctx.outputs = inputs, outputs
	}()

	if outputs {
		ctx.inputs, ctx.outputs = false, true
		origState := maps.Clone(ctx.state)
		ctx.provideOutput("ForEach", f.Item, elemType)

		f.Do.verify(ctx)

		f.loopVars = make(map[string]reflect.Type)
		for name, desc := range ctx.state {
			if origState[name] == nil && name != f.Item {
				f.loopVars[name] = desc.typ
			}
		}

		// Remove the item from the state as it's temporary.
		delete(ctx.state, f.Item)
	}

	if inputs {
		ctx.inputs, ctx.outputs = true, false
		ctx.state[f.Item] = &varState{action: "ForEach", typ: elemType, used: false}

		f.Do.verify(ctx)

		if !ctx.state[f.Item].used {
			ctx.errorf("ForEach", "item %v is unused", f.Item)
		}
		delete(ctx.state, f.Item)
	}
}
