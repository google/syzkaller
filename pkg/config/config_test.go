// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	type NestedNested struct {
		Ccc int
		Ddd string
	}
	type Nested struct {
		Aaa  int
		Bbb  string
		More NestedNested
	}
	type Config struct {
		Foo int
		Bar string
		Baz string `json:"-"`
		Raw json.RawMessage
		Qux []string
		Box Nested
		Boq *Nested
		Arr []Nested
		T   time.Time
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
		{
			`{"foo": 1, "box": {"aaa": 12, "bbb": "bbb"}}`,
			Config{
				Foo: 1,
				Box: Nested{
					Aaa: 12,
					Bbb: "bbb",
				},
			},
			"",
		},
		{
			`{"qux": ["aaa", "bbb"]}`,
			Config{
				Qux: []string{"aaa", "bbb"},
			},
			"",
		},
		{
			`{"box": {"aaa": 12, "ccc": "bbb"}}`,
			Config{},
			"unknown field 'box.ccc' in config",
		},
		{
			`{"foo": 1, "boq": {"aaa": 12, "bbb": "bbb"}}`,
			Config{
				Foo: 1,
				Boq: &Nested{
					Aaa: 12,
					Bbb: "bbb",
				},
			},
			"",
		},
		{
			`{"boq": {"aaa": 12, "ccc": "bbb"}}`,
			Config{},
			"unknown field 'boq.ccc' in config",
		},

		{
			`{"foo": 1, "arr": []}`,
			Config{
				Foo: 1,
				Arr: []Nested{},
			},
			"",
		},
		{
			`{"foo": 1, "arr": [{"aaa": 12, "bbb": "bbb"}, {"aaa": 13, "bbb": "ccc"}]}`,
			Config{
				Foo: 1,
				Arr: []Nested{
					{
						Aaa: 12,
						Bbb: "bbb",
					},
					{
						Aaa: 13,
						Bbb: "ccc",
					},
				},
			},
			"",
		},
		{
			`{"arr": [{"aaa": 12, "ccc": "bbb"}]}`,
			Config{},
			"unknown field 'arr[0].ccc' in config",
		},
		{
			`{"foo": 1, "boq": {"aaa": 12, "more": {"ccc": 13, "ddd": "ddd"}}}`,
			Config{
				Foo: 1,
				Boq: &Nested{
					Aaa: 12,
					More: NestedNested{
						Ccc: 13,
						Ddd: "ddd",
					},
				},
			},
			"",
		},
		{
			`{"foo": 1, "boq": {"aaa": 12, "more": {"ccc": 13, "eee": "eee"}}}`,
			Config{},
			"unknown field 'boq.more.eee' in config",
		},
		{
			`{"raw": {"zux": 11}}`,
			Config{
				Raw: []byte(`{"zux": 11}`),
			},
			"",
		},
		{
			`{"foo": null, "qux": null}`,
			Config{},
			"",
		},
		{
			`{"t": "2000-01-02T03:04:05Z"}`,
			Config{
				T: time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC),
			},
			"",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var cfg Config
			err := LoadData([]byte(test.input), &cfg)
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			if test.err != errStr {
				t.Fatalf("bad err: want '%v', got '%v'", test.err, errStr)
			}
			if !reflect.DeepEqual(test.output, cfg) {
				t.Fatalf("bad output: want:\n%#v\n, got:\n%#v", test.output, cfg)
			}
		})
	}
}

func TestLoadBadType(t *testing.T) {
	want := "config type is not pointer to struct"
	if err := LoadData([]byte("{}"), 1); err == nil || err.Error() != want {
		t.Fatalf("got '%v', want '%v'", err, want)
	}
	i := 0
	if err := LoadData([]byte("{}"), &i); err == nil || err.Error() != want {
		t.Fatalf("got '%v', want '%v'", err, want)
	}
	s := struct{}{}
	if err := LoadData([]byte("{}"), s); err == nil || err.Error() != want {
		t.Fatalf("got '%v', want '%v'", err, want)
	}
}
