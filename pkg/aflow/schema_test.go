// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchema(t *testing.T) {
	type Test struct {
		fn  func() (*jsonschema.Schema, error)
		err string
	}
	type structWithNoTags struct {
		A int
	}
	type structWithTags struct {
		A int    `jsonschema:"aaa"`
		B string `jsonschema:"bbb"`
	}
	tests := []Test{
		{
			fn:  schemaFor[int],
			err: "int is not a struct",
		},
		{
			fn:  schemaFor[structWithNoTags],
			err: "structWithNoTags.A does not have a jsonschema tag with description",
		},
		{
			fn: schemaFor[structWithTags],
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			_, err := test.fn()
			if err != nil {
				assert.Equal(t, err.Error(), test.err)
				return
			}
			require.Empty(t, test.err)
		})
	}
}

func TestConvertFromMap(t *testing.T) {
	testConvertFromMap(t, false, map[string]any{
		"I0": -1,
		"I1": 2.0,
		"I2": 3.0,
		"S":  "foo",
		"VM": map[string]any{
			"Foo": 1,
			"Str": "str",
		},
		"unused": "unused",
	}, struct {
		I0 int
		I1 int
		I2 uint8
		S  string
		VM json.RawMessage
	}{
		I0: -1,
		I1: 2,
		I2: 3,
		S:  "foo",
		VM: json.RawMessage(`{"Foo":1,"Str":"str"}`),
	},
		"", "")

	testConvertFromMap(t, true, map[string]any{
		"I1": 2.0,
	}, struct {
		I0 int `json:"I0"`
	}{},
		`missing argument "I0"`,
		`struct { I0 int "json:\"I0\"" }: field "I0" is not present when converting map`)

	testConvertFromMap(t, true, map[string]any{
		"I0": "foo",
	}, struct {
		I0 int
	}{},
		`argument "I0" has wrong type: got string, want int`,
		`struct { I0 int }: field "I0" has wrong type: got string, want int`)

	testConvertFromMap(t, true, map[string]any{
		"I0": 1.1,
	}, struct {
		I0 int
	}{},
		`argument I0: float value truncated from 1.1 to 1`,
		`struct { I0 int }: field I0: float value truncated from 1.1 to 1`)

	testConvertFromMap(t, true, map[string]any{
		"I0": -1,
		"I1": 2.0,
	}, struct {
		I0 int
	}{},
		`unused fields when converting map to struct { I0 int }: map[I1:2]`,
		`unused fields when converting map to struct { I0 int }: map[I1:2]`)

	testConvertFromMap(t, false, map[string]any{
		"I1": 2.0,
	}, struct {
		I0 int `json:",omitempty"`
	}{},
		``,
		``)

	val5 := uint(5)
	testConvertFromMap(t, false, map[string]any{
		"P": 5.0,
	}, struct {
		P *uint
	}{
		P: &val5,
	}, "", "")

	testConvertFromMap(t, true, map[string]any{
		"P": 5.1,
	}, struct {
		P *uint
	}{},
		`argument P: float value truncated from 5.1 to 5`,
		`struct { P *uint }: field P: float value truncated from 5.1 to 5`)
}

func testConvertFromMap[T any](t *testing.T, strict bool, input map[string]any, output T, toolErr, nonToolErr string) {
	for _, tool := range []bool{true, false} {
		wantErr := nonToolErr
		if tool {
			wantErr = toolErr
		}
		got, err := convertFromMap[T](input, strict, tool)
		if err != nil {
			require.Equal(t, err.Error(), wantErr)
		} else {
			require.Empty(t, wantErr)
			require.Equal(t, got, output)
		}
	}
}
