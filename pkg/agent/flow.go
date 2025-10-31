// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"iter"
	"reflect"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"google.golang.org/adk/session"
)

type Flow struct {
	Name         string
	Experimental bool
	MajorVersion uint
	MinorVersion uint
	Root         Agent

	InputSchema    *jsonschema.Schema
	OutputSchema   *jsonschema.Schema
	ParseInputs    func([]byte) (any, error) `json:"-"`
	convertInputs  func(data any) (map[string]any, error)
	extractOutputs func(session.State) (any, error)
}

var Flows = make(map[string]*Flow)

func Register[Inputs, Outputs any](flows ...*Flow) {
	if err := register[Inputs, Outputs](flows); err != nil {
		panic(err)
	}
}

func register[Inputs, Outputs any](flows []*Flow) error {
	if typ := reflect.TypeFor[Inputs](); typ.Kind() != reflect.Struct {
		return fmt.Errorf("input type %v is not a struct", typ.Name())
	}
	if typ := reflect.TypeFor[Outputs](); typ.Kind() != reflect.Struct {
		return fmt.Errorf("output type %v is not a struct", typ.Name())
	}
	inputSchema, err := jsonschema.For[Inputs](nil)
	if err != nil {
		return fmt.Errorf("failed to create json schema for input type: %w", err)
	}
	outputSchema, err := jsonschema.For[Outputs](nil)
	if err != nil {
		return fmt.Errorf("failed to create json schema for output type: %w", err)
	}
	for _, flow := range flows {
		if Flows[flow.Name] != nil {
			return fmt.Errorf("flow %v is already registered", flow.Name)
		}
		flow.InputSchema = inputSchema
		flow.OutputSchema = outputSchema
		flow.ParseInputs = parseInputs[Inputs]
		flow.convertInputs = inputs[Inputs]
		flow.extractOutputs = outputs[Outputs]
		if err := verify[Inputs, Outputs](flow); err != nil {
			return fmt.Errorf("flow %v: %w", flow.Name, err)
		}
		Flows[flow.Name] = flow
	}
	return nil
}

const (
	inputPrefix  = "in:"
	outputPrefix = "out:"
)

func parseInputs[T any](data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var inputs T
	if err := dec.Decode(&inputs); err != nil {
		return nil, fmt.Errorf("failed to parse input data: %w", err)
	}
	return inputs, nil
}

func inputs[T any](data any) (map[string]any, error) {
	val, ok := data.(T)
	if !ok {
		return nil, fmt.Errorf("got input type %T, want %v",
			val, reflect.TypeFor[T]().Name())
	}
	values := make(map[string]any)
	for name, val := range foreachField(inputPrefix, &val) {
		values[name] = val.Interface()
	}
	return values, nil
}

func outputs[T any](s session.State) (any, error) {
	var values T
	for name, field := range foreachField(outputPrefix, &values) {
		val, err := s.Get(name)
		if err != nil {
			return nil, err
		}
		field.Set(reflect.ValueOf(val))
	}
	return values, nil
}

func verify[Inputs, Outputs any](flow *Flow) error {
	vctx := &verifyContext{
		state: make(map[string]bool),
	}
	var inputs Inputs
	for name := range foreachField(inputPrefix, &inputs) {
		vctx.state[name] = true
	}
	flow.Root.verify(vctx)
	var outputs Outputs
	for name := range foreachField(outputPrefix, &outputs) {
		if !vctx.state[name] && vctx.err == nil {
			vctx.err = fmt.Errorf("output field %q is not created", name)
		}
	}
	return vctx.err
}

func foreachField(prefix string, data any) iter.Seq2[string, reflect.Value] {
	return func(yield func(string, reflect.Value) bool) {
		v := reflect.ValueOf(data).Elem()
		for _, field := range reflect.VisibleFields(v.Type()) {
			name := field.Name
			tag := field.Tag.Get("json")
			if tag != "" && tag[0] == '-' {
				continue
			}
			if comma := strings.IndexByte(tag, ','); comma >= 0 {
				tag = tag[:comma]
			}
			if tag != "" {
				name = tag
			}
			if !yield(prefix+name, v.FieldByIndex(field.Index)) {
				break
			}
		}
	}
}

func schemaFor[T any]() (*jsonschema.Resolved, error) {
	schema, err := jsonschema.For[T](nil)
	if err != nil {
		return nil, err
	}
	fmt.Printf("GOT SCHEMA: %+v\n", *schema)
	return schema.Resolve(nil)
}
