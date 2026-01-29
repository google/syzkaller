// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var baseCommitPicker = aflow.NewFuncAction("base-commit-picker", pickBaseCommit)

type baseCommitArgs struct {
	// Can be used to override the selected base commit (for manual testing).
	FixedBaseCommit string
	FixedRepository string
}

type baseCommitResult struct {
	KernelRepo   string
	KernelCommit string
}

func pickBaseCommit(ctx *aflow.Context, args baseCommitArgs) (baseCommitResult, error) {
	// Currently we use the latest RC of the mainline tree as the base.
	// This is a reasonable choice overall in lots of cases, and it enables good caching
	// of all artifacts (we need to rebuild them only approx every week).
	// Potentially we can use subsystem trees for few important, well-maintained subsystems
	// (mm, net, etc). However, it will work poorly for all subsystems. First, there is no
	// machine-usable mapping of subsystems to repo/branch; second, lots of them are poorly
	// maintained (can be much older than latest RC); third, it will make artifact caching
	// much worse.
	// In the future we ought to support automated rebasing of patches to requested trees/commits.
	// We need it anyway, but it will also alleviate imperfect base commit picking.
	const (
		baseRepo   = "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
		baseBranch = "master"
	)

	res := baseCommitResult{
		KernelRepo:   baseRepo,
		KernelCommit: args.FixedBaseCommit,
	}
	if args.FixedRepository != "" {
		res.KernelRepo = args.FixedRepository
	}
	if args.FixedBaseCommit != "" {
		return res, nil
	}

	err := kernel.UseLinuxRepo(ctx, func(_ string, repo vcs.Repo) error {
		head, err := repo.Poll(baseRepo, baseBranch)
		if err != nil {
			return err
		}
		res.KernelCommit, err = repo.ReleaseTag(head.Hash)
		return err
	})
	return res, err
}

var getMaintainers = aflow.NewFuncAction("get-maintainers", maintainers)

type maintainersArgs struct {
	KernelSrc string
	PatchDiff string
}

type maintainersResult struct {
	Recipients []Recipient
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
		res.Recipients = append(res.Recipients, Recipient{
			Name:  recipient.Address.Name,
			Email: recipient.Address.Address,
			To:    recipient.Type == vcs.To,
		})
	}
	return res, nil
}
