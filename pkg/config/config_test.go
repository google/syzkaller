// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"fmt"
	"reflect"
	"testing"
)

func TestUnknown(t *testing.T) {
	type Config struct {
		Foo int
		Bar string
		Baz string `json:"-"`
	}
	tests := []struct {
		input  string
		output Config
		err    string
	}{
		{
			`{"foo": 42}`,
			Config{
				Foo: 42,
			},
			"",
		},
		{
			`{"BAR": "Baz", "foo": 42}`,
			Config{
				Foo: 42,
				Bar: "Baz",
			},
			"",
		},
		{
			`{"foobar": 42}`,
			Config{},
			"unknown field 'foobar' in config",
		},
		{
			`{"foo": 1, "baz": "baz", "bar": "bar"}`,
			Config{},
			"unknown field 'baz' in config",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var cfg Config
			err := load([]byte(test.input), &cfg)
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			if test.err != errStr {
				t.Fatalf("bad err: want '%v', got '%v'", test.err, errStr)
			}
			if !reflect.DeepEqual(test.output, cfg) {
				t.Fatalf("bad output: want '%#v', got '%#v'", test.output, cfg)
			}
		})
	}
}
