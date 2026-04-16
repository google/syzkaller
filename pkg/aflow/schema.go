// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"reflect"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

func schemaFor[T any]() (*jsonschema.Schema, error) {
	typ := reflect.TypeFor[T]()
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%v is not a struct", typ.Name())
	}
	if err := checkSchemaType(typ); err != nil {
		return nil, err
	}
	return uncheckedSchemaFor[T](), nil
}

func uncheckedSchemaFor[T any]() *jsonschema.Schema {
	schema, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		panic(err)
	}
	return resolved.Schema()
}

func checkSchemaType(typ reflect.Type) error {
	if typ.Kind() != reflect.Struct {
		return nil
	}
	for _, field := range reflect.VisibleFields(typ) {
		if field.Tag.Get("jsonschema") == "" {
			return fmt.Errorf("%v.%v does not have a jsonschema tag with description",
				typ.Name(), field.Name)
		}
		if err := checkSchemaType(field.Type); err != nil {
			return err
		}
		switch field.Type.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			if err := checkSchemaType(field.Type.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
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
// If tool is set, return errors in the form suitable to return back to LLM
// during tool arguments conversion.
func convertFromMap[T any](m map[string]any, strict, tool bool) (T, error) {
	var val T
	err := convertFromMapReflect(reflect.ValueOf(&val).Elem(), m, strict, tool)
	return val, err
}

func convertFromMapReflect(v reflect.Value, m map[string]any, strict, tool bool) error {
	m = maps.Clone(m)
	t := v.Type()
	for _, fieldType := range reflect.VisibleFields(t) {
		if !fieldType.IsExported() {
			continue
		}
		name := fieldType.Name
		field := v.FieldByIndex(fieldType.Index)
		f, ok := m[name]
		if !ok || f == nil {
			if strings.Contains(fieldType.Tag.Get("json"), ",omitempty") {
				continue
			}
			if tool {
				return BadCallError("missing argument %q", name)
			} else {
				return fmt.Errorf("%v: field %q is not present when converting map", t, name)
			}
		}
		delete(m, name)
		if err := setField(field, v.Interface(), f, name, tool); err != nil {
			return err
		}
	}
	if strict && len(m) != 0 {
		return fmt.Errorf("unused fields when converting map to %v: %v", t, m)
	}
	return nil
}

func setField(field reflect.Value, val, f any, name string, tool bool) error {
	fType, fValue := reflect.TypeOf(f), reflect.ValueOf(f)
	targetType := field.Type()
	if targetType.Kind() == reflect.Ptr {
		targetType = targetType.Elem()
	}
	if mm, ok := f.(map[string]any); ok && field.Type() == reflect.TypeFor[json.RawMessage]() {
		raw, err := json.Marshal(mm)
		if err != nil {
			return err
		}
		field.Set(reflect.ValueOf(json.RawMessage(raw)))
		return nil
	}
	if fType.Kind() == reflect.Float64 &&
		(reflect.Zero(targetType).CanInt() || reflect.Zero(targetType).CanUint()) {
		// Genai will send us integers as float64 after json conversion,
		// so convert them back to ints.
		iv := fValue.Convert(targetType)
		if fv := iv.Convert(fType); !fValue.Equal(fv) {
			if tool {
				return BadCallError("argument %v: float value truncated from %v to %v",
					name, f, iv.Interface())
			}
			return fmt.Errorf("%T: field %v: float value truncated from %v to %v",
				val, name, f, iv.Interface())
		}
		if field.Kind() == reflect.Ptr {
			ptr := reflect.New(targetType)
			ptr.Elem().Set(iv)
			field.Set(ptr)
		} else {
			field.Set(iv)
		}
		return nil
	}
	if field.Type() == fType {
		field.Set(fValue)
		return nil
	}

	unmarshalerType := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	if targetType.Implements(unmarshalerType) || reflect.PointerTo(targetType).Implements(unmarshalerType) {
		if raw, err := json.Marshal(f); err == nil {
			ptr := reflect.New(targetType)
			if err := json.Unmarshal(raw, ptr.Interface()); err == nil {
				if field.Type().Kind() == reflect.Ptr {
					field.Set(ptr)
				} else {
					field.Set(ptr.Elem())
				}
				return nil
			}
		}
	}

	if targetType.Kind() == reflect.Struct {
		mm, ok := f.(map[string]any)
		if !ok {
			return fmt.Errorf("field %q must be a map, got %T", name, f)
		}
		var structVal reflect.Value
		if field.Type().Kind() == reflect.Ptr {
			if field.IsNil() {
				field.Set(reflect.New(targetType))
			}
			structVal = field.Elem()
		} else {
			structVal = field
		}
		return convertFromMapReflect(structVal, mm, false, tool)
	}

	if targetType.Kind() == reflect.Slice && targetType.Elem().Kind() == reflect.Struct {
		return setSliceField(field, name, f, targetType, tool)
	}

	if tool {
		return BadCallError("argument %q has wrong type: got %T, want %v",
			name, f, field.Type().Name())
	}
	return fmt.Errorf("%T: field %q has wrong type: got %T, want %v",
		val, name, f, field.Type().Name())
}

func setSliceField(field reflect.Value, name string, f any, targetType reflect.Type, tool bool) error {
	slice, ok := f.([]any)
	if !ok {
		return fmt.Errorf("field %q must be a slice, got %T", name, f)
	}
	elemType := targetType.Elem()
	res := reflect.MakeSlice(targetType, 0, len(slice))
	for i, item := range slice {
		mm, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("item %d in field %q must be a map, got %T", i, name, item)
		}
		elem := reflect.New(elemType).Elem()
		if err := convertFromMapReflect(elem, mm, false, tool); err != nil {
			return fmt.Errorf("item %d in field %q: %w", i, name, err)
		}
		res = reflect.Append(res, elem)
	}
	field.Set(res)
	return nil
}

func extractOutputs[T any](state map[string]any) map[string]any {
	// Ensure that we actually have all outputs.
	tmp, err := convertFromMap[T](state, false, false)
	if err != nil {
		panic(err)
	}
	return convertToMap(tmp)
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
