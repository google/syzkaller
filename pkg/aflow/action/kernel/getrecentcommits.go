// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var GetRecentCommits = aflow.NewFuncAction("get-recent-commits", recentCommits)

type RecentCommitsArgs struct {
	KernelCommit string
	PatchDiff    string
}

type RecentCommitsResult struct {
	RecentCommits string
}

func recentCommits(ctx *aflow.Context, args RecentCommitsArgs) (RecentCommitsResult, error) {
	var res RecentCommitsResult
	var files []string
	for _, file := range vcs.ParseGitDiff([]byte(args.PatchDiff)) {
		files = append(files, file.Name)
	}
	if len(files) == 0 {
		return res, aflow.FlowError(errors.New("patch diff does not contain any modified files"))
	}
	// We need to run git log in the master git repo b/c out KernelSrc/KernelScratchSrc
	// are shallow checkouts that don't have history.
	err := UseLinuxRepo(ctx, func(kernelRepoDir string, _ vcs.Repo) error {
		gitArgs := append([]string{"log", "--format=%s", "--no-merges", "-n", "20", args.KernelCommit}, files...)
		output, err := osutil.RunCmd(10*time.Minute, kernelRepoDir, "git", gitArgs...)
		if err != nil {
			return aflow.FlowError(fmt.Errorf("%w\n%s", err, output))
		}
		res.RecentCommits = string(output)
		return nil
	})
	return res, err
}
