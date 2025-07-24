// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestSelectTrees(t *testing.T) {
	trees := []*api.Tree{
		{
			Name:       "mainline",
			EmailLists: nil,
			Priority:   0,
		},
		{
			Name:       "net",
			EmailLists: []string{"net@list"},
			Priority:   1,
		},
		{
			Name:       "wireless",
			EmailLists: []string{"wireless@list"},
			Priority:   2,
		},
		{
			Name:       "bpf",
			EmailLists: []string{"bpf@list"},
			Priority:   3,
		},
		{
			Name:       "test",
			Priority:   api.TreePriorityNever,
			EmailLists: []string{"test@list"},
		},
	}
	tests := []struct {
		testName string
		result   []string
		series   *api.Series
	}{
		{
			testName: "only-net",
			result:   []string{"net", "mainline"},
			series:   &api.Series{Cc: []string{"net@list"}},
		},
		{
			testName: "prefer-wireless",
			result:   []string{"wireless", "net", "mainline"},
			series:   &api.Series{Cc: []string{"net@list", "wireless@list"}},
		},
		{
			testName: "fallback",
			result:   []string{"mainline"},
			series:   &api.Series{Cc: []string{"unknown@list"}},
		},
		{
			testName: "prefer-direct-match",
			result:   []string{"test", "wireless", "net", "mainline"},
			series: &api.Series{
				Cc:          []string{"net@list", "wireless@list"},
				SubjectTags: []string{"test"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			ret := SelectTrees(test.series, trees)
			var retNames []string
			for _, tree := range ret {
				retNames = append(retNames, tree.Name)
			}
			assert.Equal(t, test.result, retNames)
		})
	}
}
