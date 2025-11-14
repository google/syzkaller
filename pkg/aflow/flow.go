// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

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
	// The following fields must be set when a workflow is defined.
	Name         string
	Description  string
	Experimental bool
	MajorVersion uint
	MinorVersion uint
	Root         Action

	// The following fields are filled automatically when the flow is registered.
	InputSchema  *jsonschema.Schema
	OutputSchema *jsonschema.Schema
	//ParseInputs    func([]byte) (any, error)
	convertOutputs func(map[string]any) (any, error)
	//convertInputs  func(session.State, any) error
	extractOutputs func(session.State) (any, error)
}

var Flows = make(map[string]*Flow)

func Register[Inputs, Outputs any](flows ...*Flow) {
	if err := register[Inputs, Outputs](Flows, flows); err != nil {
		panic(err)
	}
}

func register[Inputs, Outputs any](all map[string]*Flow, flows []*Flow) error {
	inputSchema, err := schemaFor[Inputs]()
	if err != nil {
		return err
	}
	outputSchema, err := schemaFor[Outputs]()
	if err != nil {
		return err
	}
	for _, flow := range flows {
		registerOne[Inputs, Outputs](all, inputSchema, outputSchema, flow)
	}
	return nil
}

func registerOne[Inputs, Outputs any](all map[string]*Flow, inputSchema, outputSchema *jsonschema.Schema,
	flow *Flow) error {
	if all[flow.Name] != nil {
		return fmt.Errorf("flow %v is already registered", flow.Name)
	}
	flow.InputSchema = inputSchema
	flow.OutputSchema = outputSchema
	//flow.ParseInputs = parseTo[Inputs]
	flow.convertOutputs = convertTo[Outputs, map[string]any]
	//flow.convertInputs = storeToState[Inputs]
	flow.extractOutputs = extractFromState[Outputs]
	if err := verify[Inputs, Outputs](flow); err != nil {
		return fmt.Errorf("flow %v: %w", flow.Name, err)
	}
	all[flow.Name] = flow
	return nil
}

func parseTo[T any](data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var v T
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("failed to parse json data: %w", err)
	}
	return v, nil
}

func convertTo[To, From any](from From) (any, error) {
	var to To
	data, err := json.Marshal(from)
	if err != nil {
		return to, fmt.Errorf("failed to marshal object: %w", err)
	}
	return parseTo[To](data)
}

func convertToMap(from any) map[string]any {
	res, err := convertTo[map[string]any](from)
	if err != nil {
		panic(err)
	}
	return res.(map[string]any)
}

func storeToState[T any](s session.State, data any) error {
	val, ok := data.(T)
	if !ok {
		return fmt.Errorf("got input type %T, want %v",
			val, reflect.TypeFor[T]().Name())
	}
	for name, val := range foreachField(&val) {
		if err := s.Set(name, val.Interface()); err != nil {
			return err
		}
	}
	return nil
}

func extractFromState[T any](s session.State) (any, error) {
	var values T
	for name, field := range foreachField(&values) {
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
			if !yield(name, v.FieldByIndex(field.Index)) {
				break
			}
		}
	}
}

func foreachFieldOf[T any]() iter.Seq2[string, reflect.Value] {
	return foreachField(new(T))
}

func schemaFor[T any]() (*jsonschema.Schema, error) {
	typ := reflect.TypeFor[T]()
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("schema type %v is not a struct", typ.Name())
	}
	schema, err := jsonschema.For[T](nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create json schema for type %v: %w", typ.Name(), err)
	}
	return schema, nil
}
