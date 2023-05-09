// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDropParam(t *testing.T) {
	tests := []struct {
		in    string
		key   string
		value string
		out   string
	}{
		{
			in:    `/upstream?first=a&second=b`,
			key:   `first`,
			value: ``,
			out:   `/upstream?second=b`,
		},
		{
			in:    `/upstream?first=a&first=b&second=c`,
			key:   `second`,
			value: ``,
			out:   `/upstream?first=a&first=b`,
		},
		{
			in:    `/upstream?first=a&first=b&second=c`,
			key:   `first`,
			value: ``,
			out:   `/upstream?second=c`,
		},
		{
			in:    `/upstream?first=a&first=b&second=c`,
			key:   `first`,
			value: `b`,
			out:   `/upstream?first=a&second=c`,
		},
	}

	for _, test := range tests {
		got := DropParam(test.in, test.key, test.value)
		assert.Equal(t, test.out, got)
	}
}
