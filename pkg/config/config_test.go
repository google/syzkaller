// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config_test

import (
	"testing"

	"github.com/google/syzkaller/pkg/config"
	"github.com/stretchr/testify/assert"
)

type testConfig struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestLoadDataComments(t *testing.T) {
	data := []byte(`# Leading comment.
{
	# Indented comment with a non-ASCII character: ü.
	"name": "foo # not a comment",
	# Another comment.
	"count": 2
}
# Trailing comment.
`)
	var cfg testConfig
	assert.NoError(t, config.LoadData(data, &cfg))
	assert.Equal(t, testConfig{Name: "foo # not a comment", Count: 2}, cfg)
}

func TestLoadDataErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		err   string
	}{
		{
			name:  "first-line",
			input: `{]`,
			err: "failed to parse config file: invalid character ']' looking for beginning of object key string" +
				" at line 1, column 2",
		},
		{
			name: "multi-line",
			input: `{
	"name": "foo",
	"count": ]
}`,
			err: "failed to parse config file: invalid character ']' looking for beginning of value" +
				" at line 3, column 11",
		},
		{
			name: "after-comments",
			input: `# Comment with a non-ASCII character: ü.
{
	# Another comment.
	"name": "foo",,
}`,
			err: "failed to parse config file: invalid character ',' looking for beginning of object key string" +
				" at line 4, column 16",
		},
		{
			name:  "non-ascii",
			input: `{"name": "ü" "count": 1}`,
			err: "failed to parse config file: invalid character '\"' after object key:value pair" +
				" at line 1, column 14",
		},
		{
			name:  "type-error",
			input: `{"count": "1"}`,
			err: "failed to parse config file: json: cannot unmarshal string into Go struct field" +
				" testConfig.count of type int",
		},
		{
			name:  "unknown-field",
			input: `{"foo": 1}`,
			err:   `failed to parse config file: json: unknown field "foo"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var cfg testConfig
			assert.EqualError(t, config.LoadData([]byte(test.input), &cfg), test.err)
		})
	}
}
