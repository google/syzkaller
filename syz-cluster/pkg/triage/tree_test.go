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
			Name:       "bpf",
			EmailLists: []string{"bpf@list"},
		},
		{
			Name:       "wireless",
			EmailLists: []string{"wireless@list"},
		},
		{
			Name:       "net",
			EmailLists: []string{"net@list"},
		},
		{
			Name:       "test",
			EmailLists: []string{"test@list"},
		},
		{
			Name:       "mainline",
			EmailLists: nil,
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

func TestTreeFromBranch(t *testing.T) {
	trees := []*api.Tree{{Name: "a"}, {Name: "b"}}
	treeIdx, branch := FindTree(trees, "a/some_branch")
	assert.Equal(t, 0, treeIdx)
	assert.Equal(t, "some_branch", branch)
	treeIdx, branch = FindTree(trees, "b/some_branch")
	assert.Equal(t, 1, treeIdx)
	assert.Equal(t, "some_branch", branch)
	treeIdx, _ = FindTree(trees, "c/some_branch")
	assert.Equal(t, -1, treeIdx)
}
