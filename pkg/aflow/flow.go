// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"reflect"
	"slices"
	"strings"
	"unicode"
)

type Flow struct {
	Name    string
	Version uint
	Root    Action

	*FlowType
}

type FlowType struct {
	Type        string
	Description string

	UnmarshalInputs func([]byte) (any, error)
	compactInputs   func(any) map[string]any
	outputsToMap    func(any) map[string]any
	outputsFromMap  func(map[string]any) (any, error)
}

var Flows = make(map[string]*Flow)

func Register[Inputs, Outputs any](name, description string, flows ...*Flow) {
	if err := register[Inputs, Outputs](name, description, Flows, flows); err != nil {
		panic(err)
	}
}

func register[Inputs, Outputs any](name, description string, all map[string]*Flow, flows []*Flow) error {
	typ := &FlowType{
		Type:            name,
		Description:     description,
		UnmarshalInputs: unmarshalData[Inputs],
		compactInputs:   compactData[Inputs],
		outputsToMap:    convertToMap[Outputs],
		outputsFromMap:  convertFromMap[Outputs],
	}
	for _, flow := range flows {
		flow.Name = name + "-" + flow.Name
		flow.FlowType = typ
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
			return ctx.inputs.(Inputs), nil
		}),
		flow.Root,
		newFuncAction("flow outputs", false, func(ctx *Context, args Outputs) (struct{}, error) {
			ctx.outputs = args
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

func convertToMap[T any](data any) map[string]any {
	res := make(map[string]any)
	val := data.(T)
	for name, val := range foreachField(&val) {
		res[name] = val.Interface()
	}
	return res
}

func convertFromMap[T any](m map[string]any) (any, error) {
	return convertFromMapImpl[T](m, false)
}

func convertFromMapImpl[T any](m map[string]any, disallowUnknown bool) (any, error) {
	m = maps.Clone(m)
	var val T
	for name, field := range foreachField(&val) {
		f, ok := m[name]
		if !ok {
			return nil, fmt.Errorf("field %v is not present when converting map to %T", name, val)
		}
		delete(m, name)
		if mm, ok := f.(map[string]any); ok && field.Type() == reflect.TypeFor[json.RawMessage]() {
			raw, err := json.Marshal(mm)
			if err != nil {
				return nil, err
			}
			field.Set(reflect.ValueOf(json.RawMessage(raw)))
		} else {
			field.Set(reflect.ValueOf(f))
		}
	}
	if disallowUnknown && len(m) != 0 {
		unused := slices.Collect(maps.Keys(m))
		slices.Sort(unused)
		return nil, fmt.Errorf("unused values when converting map to %T: %q", val, unused)
	}
	return val, nil
}

func unmarshalData[T any](data []byte) (any, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return convertFromMapImpl[T](m, true)
}

func compactData[T any](data any) map[string]any {
	// Remove fields that are too verbose for journalling (these are marked with aflow:"-" tag).
	// This is used to avoid logging e.g. full kernel config in flow inputs.
	m := make(map[string]any)
	v := reflect.ValueOf(data)
	for _, field := range reflect.VisibleFields(v.Type()) {
		name, omit := fieldName(field)
		if !omit {
			m[name] = v.FieldByIndex(field.Index).Interface()
		}
	}
	return m
}

// foreachField iterates over all public fields of the struct provided in data.
// The name (first return value) matches the name when the field is serialized in json.
// We could serialize the struct to json, and deserialize back into map[string]any,
// and then use the map, but it would miss omitempty fields.
func foreachField(data any) iter.Seq2[string, reflect.Value] {
	return func(yield func(string, reflect.Value) bool) {
		v := reflect.ValueOf(data).Elem()
		for _, field := range reflect.VisibleFields(v.Type()) {
			name, _ := fieldName(field)
			if name == "" {
				continue
			}
			if !yield(name, v.FieldByIndex(field.Index)) {
				break
			}
		}
	}
}

func fieldName(field reflect.StructField) (string, bool) {
	// Use json tag name if present, otherwise convert CamelCase to camel-case.
	var b strings.Builder
	for i, c := range field.Name {
		if unicode.IsUpper(c) {
			if i != 0 {
				b.WriteByte('-')
			}
			c = unicode.ToLower(c)
		}
		b.WriteRune(c)
	}
	name := b.String()
	jsonTag := field.Tag.Get("json")
	if jsonTag != "" && jsonTag[0] == '-' {
		return "", false
	}
	jsonTag, _, _ = strings.Cut(jsonTag, ",")
	if jsonTag != "" {
		name = jsonTag
	}
	omit := field.Tag.Get("aflow") == "-"
	return name, omit
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
