// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"log"
	"time"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

// TODO: Some further improvements:
//   1. Consider the blob hashes incorporated into the git diff. These may restrict the set of base commits.
//   2. Add support for experimental sessions: these may be way behind the current HEAD.

type TreeOps interface {
	HeadCommit(tree *api.Tree) (*vcs.Commit, error)
	ApplySeries(commit string, patches [][]byte) error
}

type CommitSelector struct {
	ops TreeOps
}

func NewCommitSelector(ops TreeOps) *CommitSelector {
	return &CommitSelector{ops: ops}
}

// Select returns the best matching commit hash.
func (cs *CommitSelector) Select(series *api.Series, tree *api.Tree, lastBuild *api.Build) (string, error) {
	head, err := cs.ops.HeadCommit(tree)
	if err != nil || head == nil {
		return "", err
	}
	log.Printf("current HEAD: %q (%v)", head.Hash, head.Date)
	// If the series is already too old, it may be incompatible even if it applies cleanly.
	const seriesLagsBehind = time.Hour * 24 * 7
	if diff := head.CommitDate.Sub(series.PublishedAt); series.PublishedAt.Before(head.CommitDate) &&
		diff > seriesLagsBehind {
		log.Printf("the series is too old: %v before the HEAD", diff)
		return "", nil
	}

	// Algorithm:
	// 1. If the last successful build is sufficiently new, prefer it over the last master.
	// We should it be renewing it regularly, so the commit should be quite up to date.
	// 2. If the last build is too old / the series does not apply, give a chance to the
	// current HEAD.

	var hashes []string
	if lastBuild != nil {
		// Check if the commit is still good enough.
		if diff := head.CommitDate.Sub(lastBuild.CommitDate); diff > seriesLagsBehind {
			log.Printf("the last successful build is already too old: %v, skipping", diff)
		} else {
			hashes = append(hashes, lastBuild.CommitHash)
		}
	}
	for _, hash := range append(hashes, head.Hash) {
		log.Printf("considering %q", hash)
		err := cs.ops.ApplySeries(hash, series.PatchBodies())
		if err == nil {
			log.Printf("series can be applied to %q", hash)
			return hash, nil
		} else {
			log.Printf("failed to apply to %q: %v", hash, err)
		}
	}
	return "", nil
}
