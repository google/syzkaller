// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"os"
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

var checkoutMu sync.Mutex

func checkout(ctx *aflow.Context, args checkoutArgs) (checkoutResult, error) {
	checkoutMu.Lock()
	defer checkoutMu.Unlock()

	res := checkoutResult{
		KernelCommit: args.KernelCommit,
	}
	kernelRepoDir := filepath.Join(ctx.Workdir, "repo", targets.Linux)
	repo, err := vcs.NewRepo(targets.Linux, "", kernelRepoDir)
	if err != nil {
		return res, err
	}
	if !vcs.CheckCommitHash(args.KernelCommit) {
		com, err := repo.CheckoutCommit(args.KernelRepo, args.KernelCommit)
		if err != nil {
			return res, err
		}
		res.KernelCommit = com.Hash
	}

	// TODO: cleanup these dirs.
	srcDir := filepath.Join(ctx.Workdir, "src")
	res.KernelSrc = filepath.Join(srcDir, res.KernelCommit)
	if osutil.IsExist(res.KernelSrc) {
		return res, nil
	}

	if _, err := repo.SwitchCommit(res.KernelCommit); err != nil {
		if _, err := repo.CheckoutCommit(args.KernelRepo, res.KernelCommit); err != nil {
			return res, err
		}
	}
	if err := osutil.MkdirAll(srcDir); err != nil {
		return res, err
	}
	tmpName := res.KernelCommit + ".tmp"
	_, err = osutil.RunCmd(time.Hour, srcDir,
		"git", "clone", "--depth", "1", "--single-branch", "--reference", kernelRepoDir, kernelRepoDir, tmpName)
	if err != nil {
		return res, err
	}
	if err := os.Rename(filepath.Join(srcDir, tmpName), res.KernelSrc); err != nil {
		return res, err
	}
	return res, nil
}
