// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestCommitSelector(t *testing.T) {
	allApply := map[string]bool{"head": true, "build": true}
	tests := []struct {
		name   string
		ops    TreeOps
		series *api.Series
		last   *api.Build
		commit string
	}{
		{
			name:   "fresh series, no last build",
			series: &api.Series{PublishedAt: date("2020-Jan-15")},
			ops:    newTestGitOps(&vcs.Commit{Hash: "head", CommitDate: date("2020-Jan-10")}, allApply),
			commit: "head",
		},
		{
			name:   "fresh series with a fresh last build",
			series: &api.Series{PublishedAt: date("2020-Jan-15")},
			ops:    newTestGitOps(&vcs.Commit{Hash: "head", CommitDate: date("2020-Jan-10")}, allApply),
			last:   &api.Build{CommitHash: "build", CommitDate: date("2020-Jan-06")},
			commit: "build",
		},
		{
			name:   "fresh series with a too old last build",
			series: &api.Series{PublishedAt: date("2020-Jan-15")},
			ops:    newTestGitOps(&vcs.Commit{Hash: "head", CommitDate: date("2020-Jan-10")}, allApply),
			last:   &api.Build{CommitHash: "build", CommitDate: date("2019-Dec-20")},
			commit: "head",
		},
		{
			name:   "slightly old series, no last build",
			series: &api.Series{PublishedAt: date("2020-Jan-15")},
			ops:    newTestGitOps(&vcs.Commit{Hash: "head", CommitDate: date("2020-Jan-20")}, allApply),
			commit: "head",
		},
		{
			name:   "a too old series",
			series: &api.Series{PublishedAt: date("2020-Jan-15")},
			ops:    newTestGitOps(&vcs.Commit{Hash: "head", CommitDate: date("2020-Feb-15")}, allApply),
			commit: "",
		},
		{
			name:   "doesn't apply to the known build",
			series: &api.Series{PublishedAt: date("2020-Jan-15")},
			ops: newTestGitOps(
				&vcs.Commit{Hash: "head", CommitDate: date("2020-Jan-13")},
				map[string]bool{"head": true, "build": false},
			),
			last:   &api.Build{CommitHash: "build", CommitDate: date("2020-Jan-10")},
			commit: "head",
		},
		{
			name:   "doesn't apply anywhere",
			series: &api.Series{PublishedAt: date("2020-Jan-15")},
			ops: newTestGitOps(
				&vcs.Commit{Hash: "head", CommitDate: date("2020-Jan-13")},
				nil,
			),
			last:   &api.Build{CommitHash: "build", CommitDate: date("2020-Jan-10")},
			commit: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selector := NewCommitSelector(test.ops)
			commit, err := selector.Select(test.series, testTree, test.last)
			assert.NoError(t, err)
			assert.Equal(t, test.commit, commit)
		})
	}
}

func date(date string) time.Time {
	t, err := time.Parse("2006-Jan-02", date)
	if err != nil {
		panic(err)
	}
	return t
}

var testTree = &api.Tree{} // all tests will use the same tree

type testGitOps struct {
	applies map[string]bool
	head    map[*api.Tree]*vcs.Commit
}

func newTestGitOps(head *vcs.Commit, applies map[string]bool) *testGitOps {
	return &testGitOps{
		applies: applies,
		head: map[*api.Tree]*vcs.Commit{
			testTree: head,
		},
	}
}

func (ops *testGitOps) HeadCommit(tree *api.Tree) (*vcs.Commit, error) {
	return ops.head[tree], nil
}

func (ops *testGitOps) ApplySeries(commit string, _ [][]byte) error {
	if ops.applies[commit] {
		return nil
	}
	return fmt.Errorf("didn't apply")
}
