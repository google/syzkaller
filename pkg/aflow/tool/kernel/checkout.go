// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

var Checkout = aflow.NewFuncAction("kernel-checkouter", checkout)

type checkoutArgs struct {
	KernelRepo string `json:"kernel-repo"`
	// Commit or branch name.
	KernelCommit string `json:"kernel-commit"`
}

type checkoutResult struct {
	// Directory with the checked out sources.
	KernelSrc string `json:"kernel-src"`
	// Always the actual commit hash, even if the input was a branch name.
	KernelCommit string `json:"kernel-commit"`
}

var repoMu sync.Mutex

func checkout(ctx *aflow.Context, args checkoutArgs) (checkoutResult, error) {
	repoMu.Lock()
	defer repoMu.Unlock()

	kernelRepoDir := filepath.Join(ctx.Workdir, "repo", targets.Linux)
	repo, err := vcs.NewRepo(targets.Linux, "", kernelRepoDir)
	if err != nil {
		return checkoutResult{}, err
	}
	kernelCommit := args.KernelCommit
	if !vcs.CheckCommitHash(kernelCommit) {
		com, err := repo.CheckoutCommit(args.KernelRepo, kernelCommit)
		if err != nil {
			return checkoutResult{}, err
		}
		kernelCommit = com.Hash
	}

	dir, err := ctx.Cache("src", kernelCommit, func(dir string) error {
		if _, err := repo.SwitchCommit(kernelCommit); err != nil {
			if _, err := repo.CheckoutCommit(args.KernelRepo, kernelCommit); err != nil {
				return err
			}
		}
		if _, err = osutil.RunCmd(time.Hour, dir, "git", "init"); err != nil {
			return err
		}
		if _, err = osutil.RunCmd(time.Hour, dir, "git", "remote", "add", "origin", kernelRepoDir); err != nil {
			return err
		}
		if _, err = osutil.RunCmd(time.Hour, dir, "git", "pull", "origin", "HEAD", "--depth=1", "--allow-unrelated-histories"); err != nil {
			return err
		}
		return nil
	})

	return checkoutResult{
		KernelSrc:    dir,
		KernelCommit: kernelCommit,
	}, err
}
