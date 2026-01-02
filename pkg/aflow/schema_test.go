// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
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
