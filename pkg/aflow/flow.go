// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"encoding/json"
	"fmt"
	"iter"
	"reflect"
)

type FlowType struct {
	Type        string
	Description string
}

type Flow struct {
	Name string // Empty for the main workflow for the workflow type.
	Root Action

	*FlowType
}

var Flows = make(map[string]*Flow)

func Register[Inputs, Outputs any](typ, description string, flows ...*Flow) {
	if err := register[Inputs, Outputs](typ, description, Flows, flows); err != nil {
		panic(err)
	}
}

func register[Inputs, Outputs any](typ, description string, all map[string]*Flow, flows []*Flow) error {
	t := &FlowType{
		Type:        typ,
		Description: description,
	}
	for _, flow := range flows {
		if flow.Name == "" {
			flow.Name = typ
		} else {
			flow.Name = typ + "-" + flow.Name
		}
		flow.FlowType = t
		if err := registerOne[Inputs, Outputs](all, flow); err != nil {
			return err
		}
	}
	return nil
}

func registerOne[Inputs, Outputs any](all map[string]*Flow, flow *Flow) error {
	if all[flow.Name] != nil {
		return fmt.Errorf("flow %v is already registered", flow.Name)
	}
	flow.Root = NewPipeline(
		newFuncAction("flow inputs", false, func(ctx *Context, args struct{}) (Inputs, error) {
			return convertFromMap[Inputs](ctx.inputs)
		}),
		flow.Root,
		newFuncAction("flow outputs", false, func(ctx *Context, args Outputs) (struct{}, error) {
			ctx.outputs = convertToMap(args)
			return struct{}{}, nil
		}),
	)
	vctx := &verifyContext{
		state: make(map[string]*varState),
	}
	flow.Root.verify(vctx)
	if err := vctx.finalize(); err != nil {
		return fmt.Errorf("flow %v: %w", flow.Name, err)
	}
	all[flow.Name] = flow
	return nil
}

func convertToMap[T any](val T) map[string]any {
	res := make(map[string]any)
	for name, val := range foreachField(&val) {
		res[name] = val.Interface()
	}
	return res
}

func convertFromMap[T any](m map[string]any) (T, error) {
	var val T
	for name, field := range foreachField(&val) {
		f, ok := m[name]
		if !ok {
			return val, fmt.Errorf("field %v is not present when converting map to %T", name, val)
		}
		if mm, ok := f.(map[string]any); ok && field.Type() == reflect.TypeFor[json.RawMessage]() {
			raw, err := json.Marshal(mm)
			if err != nil {
				return val, err
			}
			field.Set(reflect.ValueOf(json.RawMessage(raw)))
		} else {
			field.Set(reflect.ValueOf(f))
		}
	}
	return val, nil
}

// foreachField iterates over all public fields of the struct provided in data.
func foreachField(data any) iter.Seq2[string, reflect.Value] {
	return func(yield func(string, reflect.Value) bool) {
		v := reflect.ValueOf(data).Elem()
		for _, field := range reflect.VisibleFields(v.Type()) {
			if !yield(field.Name, v.FieldByIndex(field.Index)) {
				break
			}
		}
	}
}

func foreachFieldOf[T any]() iter.Seq2[string, reflect.Type] {
	return func(yield func(string, reflect.Type) bool) {
		for name, val := range foreachField(new(T)) {
			if !yield(name, val.Type()) {
				break
			}
		}
	}
}
