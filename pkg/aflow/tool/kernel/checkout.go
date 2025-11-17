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
	KernelRepo   string
	KernelCommit string
}

type checkoutResult struct {
	// Directory with the checked out sources.
	KernelSrc string
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
	dir, err := ctx.Cache("src", args.KernelCommit, func(dir string) error {
		if _, err := repo.SwitchCommit(args.KernelCommit); err != nil {
			if _, err := repo.CheckoutCommit(args.KernelRepo, args.KernelCommit); err != nil {
				return err
			}
		}
		if _, err = osutil.RunCmd(time.Hour, dir, "git", "init"); err != nil {
			return err
		}
		if _, err = osutil.RunCmd(time.Hour, dir, "git", "remote", "add", "origin", kernelRepoDir); err != nil {
			return err
		}
		if _, err = osutil.RunCmd(time.Hour, dir, "git", "pull", "origin", "HEAD", "--depth=1",
			"--allow-unrelated-histories"); err != nil {
			return err
		}
		return nil
	})
	return checkoutResult{
		KernelSrc: dir,
	}, err
}
