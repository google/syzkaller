// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddTitleStat(t *testing.T) {
	tests := []struct {
		name string
		reps [][]*Report
		want *titleStat
	}{
		{
			name: "read empty",
			want: &titleStat{},
		},
		{
			name: "add single",
			reps: [][]*Report{{{Title: "warning 1"}}},
			want: &titleStat{
				Nodes: titleStatNodes{
					"warning 1": {Count: 1},
				},
			},
		},
		{
			name: "add chain",
			reps: [][]*Report{{{Title: "warning 1"}, {Title: "warning 2"}}},
			want: &titleStat{
				Nodes: titleStatNodes{
					"warning 1": {Count: 1,
						Nodes: titleStatNodes{
							"warning 2": {Count: 1},
						},
					},
				},
			},
		},
		{
			name: "add multi chains",
			reps: [][]*Report{{{Title: "warning 1"}, {Title: "warning 2"}}, {{Title: "warning 1"}, {Title: "warning 3"}}},
			want: &titleStat{
				Nodes: titleStatNodes{
					"warning 1": {Count: 2,
						Nodes: titleStatNodes{
							"warning 2": {Count: 1},
							"warning 3": {Count: 1},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tmpFile := t.TempDir() + "/test.input"
			for _, reps := range test.reps {
				err := AddTitleStat(tmpFile, reps)
				assert.NoError(t, err)
			}
			got, err := ReadStatFile(tmpFile)
			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}
