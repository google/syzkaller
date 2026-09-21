// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
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
		head, err := repo.CheckoutBranch(args.BaseRepository, args.BaseBranch)
		if err != nil {
			return err
		}
		switch args.BaseCommit {
		case "HEAD":
			commit = head.Hash
		case "RC":
			// FetchTags is called to force fetch the tags.
			// See the discussion at https://github.com/google/syzkaller/pull/7385.
			if err := repo.FetchTags(args.BaseRepository); err != nil {
				return fmt.Errorf("failed to fetch tags: %w", err)
			}
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
	Fixes     ai.FixesTag
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
	if args.Fixes.Hash != "" && args.Fixes.AuthorEmail != "" {
		found := false
		canonicalFixesEmail := email.CanonicalEmail(args.Fixes.AuthorEmail)
		for i, rec := range res.Recipients {
			if email.CanonicalEmail(rec.Email) == canonicalFixesEmail {
				res.Recipients[i].To = true
				found = true
			}
		}
		if !found {
			res.Recipients = append(res.Recipients, ai.Recipient{
				Name:  args.Fixes.AuthorName,
				Email: args.Fixes.AuthorEmail,
				To:    true,
			})
		}
	}
	return res, nil
}

var getRecentCommits = aflow.NewFuncAction("get-recent-commits", recentCommits)

type recentCommitsArgs struct {
	KernelSrc    string
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
	// The patch may add new files, which don't exist in the checkout,
	// so we must separate the paths from the revisions.
	gitArgs := slices.Concat([]string{"log", "--format=%s", "--no-merges", "-n", "20",
		args.KernelCommit, "--"}, files)
	output, err := vcs.Git{Dir: args.KernelSrc}.Run(gitArgs...)
	if err != nil {
		return res, aflow.FlowError(err)
	}
	res.RecentCommits = string(output)
	return res, nil
}

var applyGitPatch = aflow.NewFuncAction("apply-git-patch", applyGitPatchFunc)

var forwardPatchDiff = aflow.NewFuncAction("forward-patch-diff", func(ctx *aflow.Context, args struct {
	PreviousPatchDiff string
}) (struct {
	PatchDiff string
}, error) {
	return struct{ PatchDiff string }{PatchDiff: args.PreviousPatchDiff}, nil
})

type applyGitPatchArgs struct {
	KernelScratchSrc string
	PatchHistory     []ai.PatchHistoryEntry
}

func applyGitDiff(dir, diff string) error {
	if diff == "" {
		return nil
	}
	cmd := osutil.Command("git", "apply", "-")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(diff)
	if output, err := osutil.Run(time.Minute, cmd); err != nil {
		return fmt.Errorf("failed to apply patch: %w\n%s", err, output)
	}
	return nil
}

func applyGitPatchFunc(ctx *aflow.Context, args applyGitPatchArgs) (struct{}, error) {
	if len(args.PatchHistory) == 0 {
		return struct{}{}, aflow.FlowError(fmt.Errorf("PatchHistory is empty"))
	}
	latest := args.PatchHistory[len(args.PatchHistory)-1]
	if err := applyGitDiff(args.KernelScratchSrc, latest.Diff); err != nil {
		return struct{}{}, aflow.FlowError(err)
	}
	return struct{}{}, nil
}
