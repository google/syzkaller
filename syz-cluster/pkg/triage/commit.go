// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

// TODO: Some further improvements:
//   1. Add support for experimental sessions: these may be way behind the current HEAD.

type TreeOps interface {
	HeadCommit(tree *api.Tree) (*vcs.Commit, error)
	ApplySeries(commit string, patches [][]byte) error
}

type CommitSelector struct {
	ops    TreeOps
	tracer debugtracer.DebugTracer
}

func NewCommitSelector(ops TreeOps, tracer debugtracer.DebugTracer) *CommitSelector {
	return &CommitSelector{ops: ops, tracer: tracer}
}

type SelectResult struct {
	Commit string
	Reason string // Set if Commit is empty.
}

const (
	reasonSeriesTooOld = "series lags behind the current HEAD too much"
	reasonNotApplies   = "series does not apply"
)

// Select returns the best matching commit hash.
func (cs *CommitSelector) Select(series *api.Series, tree *api.Tree) (SelectResult, error) {
	head, err := cs.ops.HeadCommit(tree)
	if err != nil || head == nil {
		return SelectResult{}, err
	}
	cs.tracer.Logf("current HEAD: %q (commit date: %v)", head.Hash, head.CommitDate)
	// If the series is already too old, it may be incompatible even if it applies cleanly.
	const seriesLagsBehind = time.Hour * 24 * 7
	if diff := head.CommitDate.Sub(series.PublishedAt); series.PublishedAt.Before(head.CommitDate) &&
		diff > seriesLagsBehind {
		cs.tracer.Logf("the series is too old: %v before the HEAD", diff)
		return SelectResult{Reason: reasonSeriesTooOld}, nil
	}

	cs.tracer.Logf("considering %q", head.Hash)
	err = cs.ops.ApplySeries(head.Hash, series.PatchBodies())
	if err == nil {
		cs.tracer.Logf("series can be applied to %q", head.Hash)
		return SelectResult{Commit: head.Hash}, nil
	}
	cs.tracer.Logf("failed to apply to %q: %v", head.Hash, err)
	return SelectResult{Reason: reasonNotApplies}, nil
}

func FromBaseCommits(series *api.Series, baseCommits []*vcs.BaseCommit, trees []*api.Tree) (*api.Tree, string) {
	// Technically, any one of baseCommits could be a good match.
	// However, the developers have their own expectations regarding
	// what tree and what branch are actually preferred there.
	// So, among baseCommits, we still give preference to those that
	// align with the mailing lists Cc'd by the patch series.
	tree, commit := bestCommit(baseCommits, SelectTrees(series, trees))
	if tree != nil {
		return tree, commit
	}
	return bestCommit(baseCommits, trees)
}

func bestCommit(baseCommits []*vcs.BaseCommit, trees []*api.Tree) (*api.Tree, string) {
	retTreeIdx, retSameBranch, retCommit := -1, false, ""
	for _, commit := range baseCommits {
		for _, commitBranch := range commit.Branches {
			treeIdx, branch := FindTree(trees, commitBranch)
			if treeIdx < 0 {
				continue
			}
			sameBranch := branch == trees[treeIdx].Branch
			// If, for the same tree, we also have matched the branch, even better.
			if retTreeIdx < 0 || treeIdx < retTreeIdx ||
				treeIdx == retTreeIdx && !retSameBranch && sameBranch {
				retTreeIdx = treeIdx
				retSameBranch = sameBranch
				retCommit = commit.Hash
			}
		}
	}
	if retTreeIdx < 0 {
		return nil, ""
	}
	return trees[retTreeIdx], retCommit
}
