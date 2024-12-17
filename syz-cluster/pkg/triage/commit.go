// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"log"
	"time"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

/*
   Some further possible improvements:
   1. Consider the blob hashes incorporated into the git diff. These may restrict the set of base commits.
   2. Add support for experimental sessions: these may be way behind the current HEAD.
*/

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

// Returns the commit hashes to try.
func (cs *CommitSelector) Select(series *api.Series, tree *api.Tree, lastBuild *api.Build) ([]string, error) {
	head, err := cs.ops.HeadCommit(tree)
	if err != nil || head == nil {
		return nil, err
	}
	log.Printf("current HEAD: %q (%v)", head.Hash, head.Date)
	// If the series is already too old, it may be incompatible even if it applies cleanly.
	const seriesLagsBehind = time.Hour * 24 * 10
	if diff := head.CommitDate.Sub(series.PublishedAt); series.PublishedAt.Before(head.CommitDate) &&
		diff > seriesLagsBehind {
		log.Printf("the series is too old: %v", diff)
		return nil, nil
	}
	hashes := []string{head.Hash}
	if lastBuild != nil {
		// Let's use the same criteria for the last built commit.
		// If it's too old already, it's better not to use it.
		if diff := head.CommitDate.Sub(lastBuild.CommitDate); diff > seriesLagsBehind {
			log.Printf("the last successful build is already too old: %v, skipping", diff)
		} else {
			hashes = append(hashes, lastBuild.CommitHash)
		}
	}
	var ret []string
	for _, hash := range hashes {
		log.Printf("considering %q", hash)
		err := cs.ops.ApplySeries(hash, series.Patches)
		if err == nil {
			log.Printf("series can be applied to %q", hash)
			ret = append(ret, hash)
		} else {
			log.Printf("failed to apply to %q: %v", hash, err)
		}
	}
	return ret, nil
}
