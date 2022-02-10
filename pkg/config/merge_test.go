// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config_test

import (
	"bytes"
	"testing"

	"github.com/google/syzkaller/pkg/config"
)

func TestMergeJSONs(t *testing.T) {
	tests := []struct {
		left   string
		right  string
		result string
	}{
		{
			`{"a":1,"b":2}`,
			`{"b":3,"c":4}`,
			`{"a":1,"b":3,"c":4}`,
		},
		{
			`{"a":1,"b":{"c":{"d":"nested string","e":"another string"}}}`,
			`{"b":{"c":{"d":12345}}}`,
			`{"a":1,"b":{"c":{"d":12345,"e":"another string"}}}`,
		},
		{
			`{}`,
			`{"a":{"b":{"c":0}}}`,
			`{"a":{"b":{"c":0}}}`,
		},
		{
			`{"a":{"b":{"c":0}}}`,
			``,
			`{"a":{"b":{"c":0}}}`,
		},
	}
	for _, test := range tests {
		res, err := config.MergeJSONs([]byte(test.left), []byte(test.right))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if !bytes.Equal(res, []byte(test.result)) {
			t.Errorf("expected %s, got %s", test.result, res)
		}
	}
}

func TestPatchJSON(t *testing.T) {
	tests := []struct {
		left   string
		patch  map[string]interface{}
		result string
	}{
		{
			`{"a":1,"b":2}`,
			map[string]interface{}{"b": "string val"},
			`{"a":1,"b":"string val"}`,
		},
		{
			`{"a":1,"b":2}`,
			map[string]interface{}{
				"a": map[string]interface{}{
					"b": map[string]interface{}{
						"c": 5,
					},
				},
			},
			`{"a":{"b":{"c":5}},"b":2}`,
		},
		{
			`{}`,
			map[string]interface{}{
				"a": map[string]interface{}{
					"b": map[string]interface{}{
						"c": 0,
					},
				},
			},
			`{"a":{"b":{"c":0}}}`,
		},
	}
	for _, test := range tests {
		res, err := config.PatchJSON([]byte(test.left), test.patch)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if !bytes.Equal(res, []byte(test.result)) {
			t.Errorf("expected %s, got %s", test.result, res)
		}
	}
}
