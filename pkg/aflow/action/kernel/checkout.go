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

// Checkout action checks out the Linux kernel on the given commit,
// outputs the source directory with the checkout.
var Checkout = aflow.NewFuncAction("kernel-checkouter", checkout)

// Checkout action checks out the Linux kernel on the given commit
// in a private temp dir that lives only for the duration of the workflow.
// It's supposed to be used for code edits.
var CheckoutScratch = aflow.NewFuncAction("kernel-scratch-checkouter", checkoutScratch)

type checkoutArgs struct {
	KernelRepo   string
	KernelCommit string
}

type checkoutResult struct {
	// Directory with the checked out sources.
	KernelSrc string
}

type checkoutScratchArgs struct {
	KernelSrc string
}

type checkoutScratchResult struct {
	// Temp dir with the checked out sources.
	KernelScratchSrc string
}

func checkout(ctx *aflow.Context, args checkoutArgs) (checkoutResult, error) {
	var res checkoutResult
	err := UseLinuxRepo(ctx, func(kernelRepoDir string, repo vcs.Repo) error {
		dir, err := ctx.Cache("src", args.KernelCommit, func(dir string) error {
			if _, err := repo.SwitchCommit(args.KernelCommit); err != nil {
				if _, err := repo.CheckoutCommit(args.KernelRepo, args.KernelCommit); err != nil {
					return err
				}
			}
			// The following commit breaks compile_commands.json by adding bogus commands that fail.
			// There is no easy way to filter out these bogus commands, so we revert the commit.
			const (
				// scripts/clang-tools: Handle included .c files in gen_compile_commands
				badCommit = "9362d34acf91a706c543d919ade3e651b9bd2d6f"
				// Revert "scripts/clang-tools: Handle included .c files in gen_compile_commands"
				revertCommit = "07fe35b766a6fcd4ec8214e5066b7b0056b6ec6a"
			)

			if ok, err := repo.Contains(revertCommit); err != nil {
				return err
			} else if !ok {
				if ok, err := repo.Contains(badCommit); err != nil {
					return err
				} else if ok {
					if _, err = osutil.RunCmd(time.Hour, kernelRepoDir,
						"git", "revert", "--no-edit", badCommit); err != nil {
						return err
					}
				}
			}
			return shallowGitClone(dir, kernelRepoDir)
		})
		res.KernelSrc = dir
		return err
	})
	return res, err
}

func checkoutScratch(ctx *aflow.Context, args checkoutScratchArgs) (checkoutScratchResult, error) {
	dir, err := ctx.TempDir()
	if err != nil {
		return checkoutScratchResult{}, err
	}
	if err := shallowGitClone(dir, args.KernelSrc); err != nil {
		return checkoutScratchResult{}, err
	}
	return checkoutScratchResult{dir}, nil
}

func shallowGitClone(dir, remoteDir string) error {
	if _, err := osutil.RunCmd(time.Hour, dir, "git", "init"); err != nil {
		return err
	}
	if _, err := osutil.RunCmd(time.Hour, dir, "git", "remote", "add", "origin", remoteDir); err != nil {
		return err
	}
	if _, err := osutil.RunCmd(time.Hour, dir, "git", "pull", "origin", "HEAD", "--depth=1",
		"--allow-unrelated-histories"); err != nil {
		return err
	}
	return nil
}

var repoMu sync.Mutex

func UseLinuxRepo(ctx *aflow.Context, fn func(string, vcs.Repo) error) error {
	repoMu.Lock()
	defer repoMu.Unlock()
	kernelRepoDir := filepath.Join(ctx.Workdir, "repo", targets.Linux)
	repo, err := vcs.NewRepo(targets.Linux, "", kernelRepoDir)
	if err != nil {
		return err
	}
	return fn(kernelRepoDir, repo)
}
