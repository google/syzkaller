// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"bytes"
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
				{{range $i, $v := .array}}
					{{$i}} {{$v}}
				{{end}}
				`,
			vars: map[string]reflect.Type{
				"array": reflect.TypeFor[[]int](),
			},
			used: []string{"array"},
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
		{
			template: `{{if and .foo .bar}} yes {{end}}`,
			vars: map[string]reflect.Type{
				"foo": reflect.TypeFor[bool](),
				"bar": reflect.TypeFor[int](),
			},
			used: []string{"foo", "bar"},
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

func TestTemplateRender(t *testing.T) {
	data := map[string]any{
		"Title": "WARNING: something is wrong",
	}
	const text = `
{{if titleIsUAF .Title}}It is UAF.{{end}}
{{if titleIsWarning .Title}}It is WARNING.{{end}}
`
	const want = `

It is WARNING.
`
	templ, err := parseTemplate(text)
	require.NoError(t, err)
	buf := new(bytes.Buffer)
	require.NoError(t, templ.Execute(buf, data))
	require.Equal(t, want, buf.String())
}
