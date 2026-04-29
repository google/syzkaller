// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var baseCommitPicker = aflow.NewFuncAction("base-commit-picker", pickBaseCommit)

type baseCommitArgs struct {
	BaseRepository string
	BaseBranch     string
	BaseCommit     string
}

type baseCommitResult struct {
	KernelRepo   string
	KernelBranch string
	KernelCommit string
}

func pickBaseCommit(ctx *aflow.Context, args baseCommitArgs) (baseCommitResult, error) {
	commit := ""
	err := kernel.UseLinuxRepo(ctx, func(_ string, repo vcs.Repo) error {
		head, err := repo.Poll(args.BaseRepository, args.BaseBranch)
		if err != nil {
			return err
		}
		switch args.BaseCommit {
		case "HEAD":
			commit = head.Hash
		case "RC":
			tag, err := repo.ReleaseTag(head.Hash)
			if err != nil {
				return err
			}
			com, err := repo.SwitchCommit(tag)
			if err != nil {
				return err
			}
			commit = com.Hash
		default:
			com, err := repo.SwitchCommit(args.BaseCommit)
			if err != nil {
				return err
			}
			commit = com.Hash
		}
		return err
	})
	return baseCommitResult{
		KernelRepo:   args.BaseRepository,
		KernelBranch: args.BaseBranch,
		KernelCommit: commit,
	}, err
}

var getMaintainers = aflow.NewFuncAction("get-maintainers", maintainers)

type maintainersArgs struct {
	KernelSrc string
	PatchDiff string
}

type maintainersResult struct {
	Recipients []ai.Recipient
}

func maintainers(ctx *aflow.Context, args maintainersArgs) (maintainersResult, error) {
	res := maintainersResult{}
	// See #1441 re --git-min-percent.
	script := filepath.Join(args.KernelSrc, "scripts/get_maintainer.pl")
	cmd := exec.Command(script, "--git-min-percent=15")
	cmd.Dir = args.KernelSrc
	cmd.Stdin = strings.NewReader(args.PatchDiff)
	output, err := osutil.Run(time.Minute, cmd)
	if err != nil {
		return res, err
	}
	for _, recipient := range vcs.ParseMaintainersLinux(output) {
		res.Recipients = append(res.Recipients, ai.Recipient{
			Name:  recipient.Address.Name,
			Email: recipient.Address.Address,
			To:    recipient.Type == vcs.To,
		})
	}
	return res, nil
}

var getRecentCommits = aflow.NewFuncAction("get-recent-commits", recentCommits)

type recentCommitsArgs struct {
	KernelCommit string
	PatchDiff    string
}

type recentCommitsResult struct {
	RecentCommits string
}

func recentCommits(ctx *aflow.Context, args recentCommitsArgs) (recentCommitsResult, error) {
	var res recentCommitsResult
	var files []string
	for _, file := range vcs.ParseGitDiff([]byte(args.PatchDiff)) {
		files = append(files, file.Name)
	}
	if len(files) == 0 {
		return res, aflow.FlowError(errors.New("patch diff does not contain any modified files"))
	}
	// We need to run git log in the master git repo b/c out KernelSrc/KernelScratchSrc
	// are shallow checkouts that don't have history.
	err := kernel.UseLinuxRepo(ctx, func(kernelRepoDir string, _ vcs.Repo) error {
		gitArgs := append([]string{"log", "--format=%s", "--no-merges", "-n", "20", args.KernelCommit}, files...)
		output, err := osutil.RunCmd(10*time.Minute, kernelRepoDir, "git", gitArgs...)
		if err != nil {
			return aflow.FlowError(err)
		}
		res.RecentCommits = string(output)
		return nil
	})
	return res, err
}

var formatPatchDescription = aflow.NewFuncAction("format-patch-description", formatDescription)

type formatDescriptionArgs struct {
	PatchDescriptionRaw string
}

type formatDescriptionResult struct {
	PatchDescription string
}

func formatDescription(ctx *aflow.Context, args formatDescriptionArgs) (formatDescriptionResult, error) {
	return formatDescriptionResult{
		PatchDescription: email.WordWrap(args.PatchDescriptionRaw, 72),
	}, nil
}

var applyGitPatch = aflow.NewFuncAction("apply-git-patch", applyGitPatchFunc)

type applyGitPatchArgs struct {
	KernelScratchSrc string
	PatchHistory     []ai.PatchHistoryEntry
}

func applyGitPatchFunc(ctx *aflow.Context, args applyGitPatchArgs) (struct{}, error) {
	if len(args.PatchHistory) == 0 {
		return struct{}{}, aflow.FlowError(fmt.Errorf("PatchHistory is empty"))
	}
	latest := args.PatchHistory[len(args.PatchHistory)-1]
	if latest.Diff == "" {
		return struct{}{}, nil
	}

	// Apply the diff.
	cmd := exec.Command("git", "apply")
	cmd.Dir = args.KernelScratchSrc
	cmd.Stdin = strings.NewReader(latest.Diff)
	if _, err := osutil.Run(time.Minute, cmd); err != nil {
		return struct{}{}, aflow.FlowError(fmt.Errorf("failed to apply previous patch: %w", err))
	}

	return struct{}{}, nil
}
