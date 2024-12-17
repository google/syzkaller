// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

// TODO: Check out branches and commits from Fuchsia's global integration repo
// rather than fuchsia.git.
type fuchsia struct {
	dir  string
	repo *gitRepo
}

func newFuchsia(dir string, opts []RepoOpt) *fuchsia {
	// For now, don't clean up the Fuchsia repo when checking out new commits or branches.
	// Otherwise, subsequent builds will fail due to missing GN args and other build configuration.
	// TODO: Implement selective cleanup with `fx clean`.
	opts = append(opts, OptPrecious)
	return &fuchsia{
		dir:  dir,
		repo: newGitRepo(dir, nil, opts),
	}
}

func (ctx *fuchsia) Poll(repo, branch string) (*Commit, error) {
	if repo != "https://fuchsia.googlesource.com/fuchsia" || (branch != "main" && branch != "master") {
		// Fuchsia ecosystem is hard-wired to the main repo + branch.
		// The 'master' branch is a mirror of 'main'.
		return nil, fmt.Errorf(
			"fuchsia: can only check out 'main' or 'master' branch of https://fuchsia.googlesource.com/fuchsia",
		)
	}
	if _, err := runSandboxed(ctx.dir, "./.jiri_root/bin/jiri", "update"); err != nil {
		if err := ctx.initRepo(); err != nil {
			return nil, err
		}
	}
	return ctx.repo.Commit(HEAD)
}

func (ctx *fuchsia) initRepo() error {
	if err := os.RemoveAll(ctx.dir); err != nil {
		return fmt.Errorf("failed to remove repo dir: %w", err)
	}
	tmpDir := ctx.dir + ".tmp"
	if err := osutil.MkdirAll(tmpDir); err != nil {
		return fmt.Errorf("failed to create repo dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	if err := osutil.SandboxChown(tmpDir); err != nil {
		return err
	}
	cmd := "curl -s 'https://fuchsia.googlesource.com/fuchsia/+/main/scripts/bootstrap?format=TEXT' |" +
		"base64 --decode | bash"
	// TODO: Remove the second `jiri update` once the `prebuilt_versions` hook is fixed.
	// Expect and ignore an error from the bootstrap script's invocation of `jiri update`.
	_, _ = runSandboxed(tmpDir, "bash", "-c", cmd)
	// Run `jiri update` a second time; it should succeed.
	if _, err := runSandboxed(filepath.Join(tmpDir, "fuchsia"), "./.jiri_root/bin/jiri", "update"); err != nil {
		return err
	}
	return osutil.Rename(filepath.Join(tmpDir, "fuchsia"), ctx.dir)
}

func (ctx *fuchsia) CheckoutBranch(repo, branch string) (*Commit, error) {
	return ctx.repo.CheckoutBranch(repo, branch)
}

func (ctx *fuchsia) CheckoutCommit(repo, commit string) (*Commit, error) {
	return ctx.repo.CheckoutCommit(repo, commit)
}

func (ctx *fuchsia) SwitchCommit(commit string) (*Commit, error) {
	return ctx.repo.SwitchCommit(commit)
}

func (ctx *fuchsia) Commit(commit string) (*Commit, error) {
	return ctx.repo.Commit(commit)
}

func (ctx *fuchsia) GetCommitByTitle(title string) (*Commit, error) {
	return ctx.repo.GetCommitByTitle(title)
}

func (ctx *fuchsia) GetCommitsByTitles(titles []string) ([]*Commit, []string, error) {
	return ctx.repo.GetCommitsByTitles(titles)
}

func (ctx *fuchsia) ExtractFixTagsFromCommits(baseCommit, email string) ([]*Commit, error) {
	return ctx.repo.ExtractFixTagsFromCommits(baseCommit, email)
}

func (ctx *fuchsia) ReleaseTag(commit string) (string, error) {
	return ctx.repo.ReleaseTag(commit)
}

func (ctx *fuchsia) Contains(commit string) (bool, error) {
	return ctx.repo.Contains(commit)
}

func (ctx *fuchsia) ListCommitHashes(baseCommit string, from time.Time) ([]string, error) {
	return ctx.repo.ListCommitHashes(baseCommit, from)
}

func (ctx *fuchsia) Object(name, commit string) ([]byte, error) {
	return ctx.repo.Object(name, commit)
}

func (ctx *fuchsia) MergeBases(firstCommit, secondCommit string) ([]*Commit, error) {
	return ctx.repo.MergeBases(firstCommit, secondCommit)
}

func (ctx *fuchsia) CommitExists(commit string) (bool, error) {
	return ctx.repo.CommitExists(commit)
}

func (ctx *fuchsia) PushCommit(repo, commit string) error {
	// Fuchsia repo doesn't accept unauthenticated pushes.
	return fmt.Errorf("not implemented for fuchsia: PushCommit")
}
