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
		{
			Name:       "stable-5.15",
			EmailLists: []string{"stable@vger.kernel.org"},
			Type:       "stable",
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
		{
			testName: "lts-rc-5.15-review",
			result:   []string{"stable-5.15"},
			series: &api.Series{
				Cc:          []string{"stable@vger.kernel.org"},
				SubjectTags: []string{"5.15"},
				Title:       "5.15.138-rc1 review",
			},
		},
		{
			testName: "developer-stable-backport-should-skip",
			result:   nil,
			series: &api.Series{
				Cc:          []string{"stable@vger.kernel.org"},
				SubjectTags: []string{"5.15"},
				Title:       "net: fix foo",
			},
		},
		{
			testName: "lts-rc-no-matching-tree",
			result:   nil,
			series: &api.Series{
				Cc:          []string{"stable@vger.kernel.org"},
				SubjectTags: []string{"5.16"},
				Title:       "5.16.138-rc1 review",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			candidateTrees, err := CandidateTrees(trees, test.series)
			if test.result == nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				selectedTrees := SelectTrees(test.series, candidateTrees)
				var retNames []string
				for _, tree := range selectedTrees {
					retNames = append(retNames, tree.Name)
				}
				assert.Equal(t, test.result, retNames)
			}
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

func TestFindTreeByName(t *testing.T) {
	trees := []*api.Tree{{Name: "a"}, {Name: "b"}}
	assert.Equal(t, "a", FindTreeByName(trees, "a").Name)
	assert.Equal(t, "b", FindTreeByName(trees, "b").Name)
	assert.Nil(t, FindTreeByName(trees, "c"))
}
