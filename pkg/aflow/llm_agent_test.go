// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"reflect"
	"testing"
	//"github.com/stretchr/testify/assert"
	//"github.com/stretchr/testify/require"
)

func TestTemplate(t *testing.T) {
	text := `
{{if .bar}}
{{.foo}}
{{end}}
{{if $local := .bar}}
{{$local}}
{{end}}
`
	vars := map[string]reflect.Type{
		"bar": reflect.TypeFor[bool](),
		"foo": reflect.TypeFor[int](),
	}
	if _, err := verifyTemplate(text, vars); err != nil {
		t.Fatal(err)
	}
}
