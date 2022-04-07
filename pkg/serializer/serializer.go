// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package serializer

import (
	"reflect"
	"strings"

	"fmt"
	"io"
)

// Write writes Go-syntax representation of v into w.
// This is similar to fmt.Fprintf(w, "%#v", v), but properly handles pointers,
// does not write package names before types, omits struct fields with default values,
// omits type names where possible, etc. On the other hand, it currently does not
// support all types (e.g. channels and maps).
func Write(ww io.Writer, i interface{}) {
	w := writer{ww}
	v := reflect.ValueOf(i)
	if v.Kind() == reflect.Slice && (v.IsNil() || v.Len() == 0) {
		w.typ(v.Type())
		w.string("(nil)")
		return
	}
	w.do(v, false)
}

type writer struct {
	w io.Writer
}

func (w *writer) do(v reflect.Value, sliceElem bool) {
	switch v.Kind() {
	case reflect.Ptr:
		w.doPtr(v, sliceElem)
	case reflect.Interface:
		w.doInterface(v)
	case reflect.Slice:
		w.doSlice(v)
	case reflect.Struct:
		w.doStruct(v, sliceElem)
	case reflect.Bool:
		if v.Bool() {
			w.string("true")
		} else {
			w.string("false")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprintf(w.w, "%v", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		fmt.Fprintf(w.w, "%v", v.Uint())
	case reflect.String:
		fmt.Fprintf(w.w, "%q", v.String())
	case reflect.Func:
		if !v.IsNil() {
			panic("no way to serialize funcs")
		}
		fmt.Fprintf(w.w, "nil")
	default:
		panic(fmt.Sprintf("unsupported type: %#v", v.Type().String()))
	}
}

func (w *writer) doPtr(v reflect.Value, sliceElem bool) {
	if v.IsNil() {
		w.string("nil")
		return
	}
	if !sliceElem {
		w.byte('&')
	}
	if v.Elem().Kind() != reflect.Struct {
		panic(fmt.Sprintf("only pointers to structs are supported, got %v",
			v.Type().Name()))
	}
	w.do(v.Elem(), sliceElem)
}

func (w *writer) doInterface(v reflect.Value) {
	if v.IsNil() {
		w.string("nil")
		return
	}
	elem := v.Elem()
	// Handling of user types that has underlying primitive types. Consider:
	//	type T int
	//	var obj interface{} = T(42)
	// T has kind reflect.Int. But if we serialize obj as just "42", it will be turned into plain int.
	// Detect this case and serialize obj as "T(42)".
	if (elem.Kind() == reflect.Bool || elem.Kind() == reflect.String ||
		elem.Type().ConvertibleTo(reflect.TypeOf(0))) &&
		strings.Contains(elem.Type().String(), ".") {
		w.string(elem.Type().Name())
		w.byte('(')
		w.do(elem, false)
		w.byte(')')
		return
	}
	w.do(elem, false)
}

func (w *writer) doSlice(v reflect.Value) {
	if v.IsNil() || v.Len() == 0 {
		w.string("nil")
		return
	}
	w.typ(v.Type())
	sub := v.Type().Elem().Kind()
	if sub == reflect.Ptr || sub == reflect.Interface || sub == reflect.Struct {
		// Elem per-line.
		w.string("{\n")
		for i := 0; i < v.Len(); i++ {
			w.do(v.Index(i), true)
			w.string(",\n")
		}
		w.byte('}')
		return
	}
	// All on one line.
	w.byte('{')
	for i := 0; i < v.Len(); i++ {
		if i > 0 {
			w.byte(',')
		}
		w.do(v.Index(i), true)
	}
	w.byte('}')
}

func (w *writer) doStruct(v reflect.Value, sliceElem bool) {
	if !sliceElem {
		w.string(v.Type().Name())
	}
	w.byte('{')
	fieldNames := false
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if isDefaultValue(f) || !f.CanSet() {
			fieldNames = true
			break
		}
	}
	needComma := false
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if fieldNames && (isDefaultValue(f) || !f.CanSet()) {
			continue
		}
		if needComma {
			w.byte(',')
		}
		if fieldNames {
			w.string(v.Type().Field(i).Name)
			w.byte(':')
		}
		w.do(f, false)
		needComma = true
	}
	w.byte('}')
}

func (w *writer) typ(t reflect.Type) {
	switch t.Kind() {
	case reflect.Ptr:
		w.byte('*')
		w.typ(t.Elem())
	case reflect.Slice:
		w.string("[]")
		w.typ(t.Elem())
	default:
		w.string(t.Name())
	}
}

func (w *writer) string(v string) {
	io.WriteString(w.w, v)
}

func (w *writer) byte(v byte) {
	if bw, ok := w.w.(io.ByteWriter); ok {
		bw.WriteByte(v)
	} else {
		w.w.Write([]byte{v})
	}
}

func isDefaultValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Ptr:
		return v.IsNil()
	case reflect.Interface:
		return v.IsNil()
	case reflect.Slice:
		return v.IsNil() || v.Len() == 0
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !isDefaultValue(v.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.String:
		return v.String() == ""
	case reflect.Func:
		return false
	default:
		return false
	}
}
