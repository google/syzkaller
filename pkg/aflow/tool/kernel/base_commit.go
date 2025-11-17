// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"path/filepath"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

var BaseCommitPicker = aflow.NewFuncAction("base-commit-picker", baseCommitPicker)

type baseCommitArgs struct {
	FixedBaseCommit string
}

type baseCommitResult struct {
	KernelRepo   string
	KernelCommit string
}

func baseCommitPicker(ctx *aflow.Context, args baseCommitArgs) (baseCommitResult, error) {
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

	if args.FixedBaseCommit != "" {
		return baseCommitResult{
			KernelRepo:   baseRepo,
			KernelCommit: args.FixedBaseCommit,
		}, nil
	}

	repoMu.Lock()
	defer repoMu.Unlock()

	kernelRepoDir := filepath.Join(ctx.Workdir, "repo", targets.Linux)
	repo, err := vcs.NewRepo(targets.Linux, "", kernelRepoDir)
	if err != nil {
		return baseCommitResult{}, err
	}
	head, err := repo.Poll(baseRepo, baseBranch)
	if err != nil {
		return baseCommitResult{}, err
	}
	base, err := repo.ReleaseTag(head.Hash)
	if err != nil {
		return baseCommitResult{}, err
	}
	return baseCommitResult{
		KernelRepo:   baseRepo,
		KernelCommit: base,
	}, nil
}
