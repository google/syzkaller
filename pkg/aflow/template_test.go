// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplate(t *testing.T) {
	type Test struct {
		template string
		vars     map[string]reflect.Type
		used     []string
		err      string
	}
	tests := []Test{
		{
			template: `just text`,
		},
		{
			template: `
				{{if .bar}}
					{{.foo}}
				{{end}}

				{{if $local := .bar}}
					{{$local}}
				{{end}}
				`,
			vars: map[string]reflect.Type{
				"bar": reflect.TypeFor[bool](),
				"foo": reflect.TypeFor[int](),
				"baz": reflect.TypeFor[int](),
			},
			used: []string{"bar", "foo"},
		},
		{
			template: `
				{{if .bar}}
					{{.foo}}
				{{end}}
				`,
			vars: map[string]reflect.Type{
				"bar": reflect.TypeFor[bool](),
			},
			err: "input foo is not provided",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			used, err := verifyTemplate(test.template, test.vars)
			if err != nil {
				assert.Equal(t, err.Error(), test.err)
				return
			}
			require.Empty(t, test.err)
			assert.ElementsMatch(t, slices.Collect(maps.Keys(used)), test.used)
		})
	}
}
