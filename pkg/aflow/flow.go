// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"iter"
	"maps"
	"reflect"
	"strings"
)

type Flow struct {
	// The following fields must be set when a workflow is defined.
	Name         string
	Description  string
	Experimental bool
	MajorVersion uint
	MinorVersion uint
	Root         Action

	inputsToMap    func(any) map[string]any
	compactInputs  func(map[string]any) map[string]any
	outputsToMap   func(any) map[string]any
	outputsFromMap func(map[string]any) (any, error)
}

var Flows = make(map[string]*Flow)

func Register[Inputs, Outputs any](flows ...*Flow) {
	if err := register[Inputs, Outputs](Flows, flows); err != nil {
		panic(err)
	}
}

func register[Inputs, Outputs any](all map[string]*Flow, flows []*Flow) error {
	for _, flow := range flows {
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
	flow.inputsToMap = convertToMap[Inputs]
	flow.compactInputs = compactMap[Inputs]
	flow.outputsToMap = convertToMap[Outputs]
	flow.outputsFromMap = convertFromMap[Outputs]
	if err := verify[Inputs, Outputs](flow); err != nil {
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
	var val T
	for name, field := range foreachField(&val) {
		val, ok := m[name]
		if !ok {
			return nil, fmt.Errorf("field %v is not present when converting map to %T", name, val)
		}
		field.Set(reflect.ValueOf(val))
	}
	return val, nil
}

func compactMap[T any](m map[string]any) map[string]any {
	// Remove fields that are too verbose for journalling (these are marked with aflow:"-" tag).
	// This is used to avoid logging e.g. full kernel config in flow inputs.
	m = maps.Clone(m)
	typ := reflect.ValueOf(new(T)).Elem().Type()
	for _, field := range reflect.VisibleFields(typ) {
		name, omit := fieldName(field)
		if omit {
			delete(m, name)
		}
	}
	return m
}

func verify[Inputs, Outputs any](flow *Flow) error {
	vctx := &verifyContext{
		state: make(map[string]bool),
	}
	for name := range foreachFieldOf[Inputs]() {
		vctx.provideOutput("flow inputs", name, false)
	}
	flow.Root.verify(vctx)
	for name := range foreachFieldOf[Outputs]() {
		vctx.requireInput("flow outputs", name)
	}
	return vctx.err
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
	name := field.Name
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

func foreachFieldOf[T any]() iter.Seq2[string, reflect.Value] {
	return foreachField(new(T))
}
