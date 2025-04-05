// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	textBase = `line1
line2
line3`
	textBaseWithNewLine = `line0
line1
line2
line3`
	textBaseWOLine = `line2
line3`
	textBaseChangedLine = `lineX
line2
line3`
)

func TestMatching(t *testing.T) {
	type Test struct {
		name     string
		textFrom string
		textTo   string
		lineFrom int
		lineTo   int
	}
	tests := []Test{
		{
			name:     "same text matching",
			textFrom: textBase,
			textTo:   textBase,
			lineFrom: 0,
			lineTo:   0,
		},
		{
			name:     "diff matching with the new line",
			textFrom: textBase,
			textTo:   textBaseWithNewLine,
			lineFrom: 0,
			lineTo:   1,
		},
		{
			name:     "diff matching with the removed line",
			textFrom: textBase,
			textTo:   textBaseWOLine,
			lineFrom: 0,
			lineTo:   -1,
		},
		{
			name:     "diff matching with the changed line",
			textFrom: textBase,
			textTo:   textBaseChangedLine,
			lineFrom: 0,
			lineTo:   -1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := makeLineToLineMatcher(test.textFrom, test.textTo)
			assert.NotNil(t, m)
			got := m.SameLinePos(test.lineFrom)
			if got != test.lineTo {
				t.Fatalf("expected to see line %d instread of %d", test.lineTo, got)
			}
		})
	}
}
