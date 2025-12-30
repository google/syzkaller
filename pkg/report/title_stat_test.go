// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddTitlesToStatFile(t *testing.T) {
	tests := []struct {
		name        string
		titleChains [][]string
		want        *TitleStat
	}{
		{
			name: "read empty",
			want: &TitleStat{},
		},
		{
			name:        "add single",
			titleChains: [][]string{{"warning 1"}},
			want: &TitleStat{
				Count: 1,
				Nodes: titleStatNodes{
					"warning 1": {Count: 1},
				},
			},
		},
		{
			name:        "add chain",
			titleChains: [][]string{{"warning 1", "warning 2"}},
			want: &TitleStat{
				Count: 1,
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
			name:        "add multi chains",
			titleChains: [][]string{{"warning 1", "warning 2"}, {"warning 1", "warning 3"}},
			want: &TitleStat{
				Count: 2,
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
			for _, titles := range test.titleChains {
				err := AddTitlesToStatFile(tmpFile, titles)
				assert.NoError(t, err)
			}
			statData, err := ReadStatFile(tmpFile)
			assert.NoError(t, err)
			assert.Equal(t, test.want, statData)
		})
	}
}

func TestTitleStat_Explain(t *testing.T) {
	tests := []struct {
		name  string
		input [][]string
		want  []*TitleFreqRank
	}{
		{
			name: "empty",
			want: nil,
		},
		{
			name:  "single input",
			input: [][]string{{"info"}},
			want: []*TitleFreqRank{
				{
					Title: "info",
					Count: 1,
					Total: 1,
					Rank:  -1,
				},
			},
		},
		{
			name:  "single nested input",
			input: [][]string{{"info"}, {"info", "warning"}},
			want: []*TitleFreqRank{
				{
					Title: "info",
					Count: 1,
					Total: 2,
					Rank:  -1,
				},
				{
					Title: "warning",
					Count: 1,
					Total: 2,
					Rank:  -1,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ts := &TitleStat{}
			for _, input := range test.input {
				ts.Add(input)
			}
			assert.Equal(t, test.want, ts.Explain())
		})
	}
}
