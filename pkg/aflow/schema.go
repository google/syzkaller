// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
)

func schemaFor[T any]() (*jsonschema.Schema, error) {
	typ := reflect.TypeFor[T]()
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%v is not a struct", typ.Name())
	}
	for _, field := range reflect.VisibleFields(typ) {
		if field.Tag.Get("jsonschema") == "" {
			return nil, fmt.Errorf("%v.%v does not have a jsonschema tag with description",
				typ.Name(), field.Name)
		}
	}
	schema, err := jsonschema.For[T](nil)
	if err != nil {
		return nil, err
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		return nil, err
	}
	return resolved.Schema(), nil
}

func mustSchemaFor[T any]() *jsonschema.Schema {
	schema, err := schemaFor[T]()
	if err != nil {
		panic(err)
	}
	return schema
}

func convertToMap[T any](val T) map[string]any {
	res := make(map[string]any)
	for name, val := range foreachField(&val) {
		res[name] = val.Interface()
	}
	return res
}

// convertFromMap converts an untyped map to a struct.
// It always ensures that all struct fields are present in the map.
// In the strict mode it also checks that the map does not contain any other unused elements.
func convertFromMap[T any](m map[string]any, strict bool) (T, error) {
	m = maps.Clone(m)
	var val T
	for name, field := range foreachField(&val) {
		f, ok := m[name]
		if !ok {
			return val, fmt.Errorf("field %v is not present when converting map to %T", name, val)
		}
		delete(m, name)
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
	if strict && len(m) != 0 {
		return val, fmt.Errorf("unused fields when converting map to %T: %v", val, m)
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
