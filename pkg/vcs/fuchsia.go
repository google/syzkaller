// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/osutil"
)

type fuchsia struct {
	vm     string
	dir    string
	zircon *git
}

func newFuchsia(vm, dir string) *fuchsia {
	return &fuchsia{
		vm:     vm,
		dir:    dir,
		zircon: newGit("fuchsia", vm, filepath.Join(dir, "zircon")),
	}
}

func (ctx *fuchsia) Poll(repo, branch string) (*Commit, error) {
	if repo != "https://fuchsia.googlesource.com" || branch != "master" {
		// fuchsia ecosystem is hard-tailored to the main repo.
		return nil, fmt.Errorf("fuchsia: can only check out https://fuchsia.googlesource.com/master")
	}
	if _, err := runSandboxed(ctx.dir, "./.jiri_root/bin/jiri", "update"); err != nil {
		if err := ctx.initRepo(); err != nil {
			return nil, err
		}
	}
	return ctx.zircon.HeadCommit()
}

func (ctx *fuchsia) initRepo() error {
	if err := os.RemoveAll(ctx.dir); err != nil {
		return fmt.Errorf("failed to remove repo dir: %v", err)
	}
	tmpDir := ctx.dir + ".tmp"
	if err := osutil.MkdirAll(tmpDir); err != nil {
		return fmt.Errorf("failed to create repo dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	if err := osutil.SandboxChown(tmpDir); err != nil {
		return err
	}
	cmd := "curl -s 'https://fuchsia.googlesource.com/scripts/+/master/bootstrap?format=TEXT' |" +
		"base64 --decode | bash -s topaz"
	if _, err := runSandboxed(tmpDir, "bash", "-c", cmd); err != nil {
		return err
	}
	return os.Rename(filepath.Join(tmpDir, "fuchsia"), ctx.dir)
}

func (ctx *fuchsia) CheckoutBranch(repo, branch string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (ctx *fuchsia) CheckoutCommit(repo, commit string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (ctx *fuchsia) SwitchCommit(commit string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (ctx *fuchsia) HeadCommit() (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (ctx *fuchsia) ListRecentCommits(baseCommit string) ([]string, error) {
	return ctx.zircon.ListRecentCommits(baseCommit)
}

func (ctx *fuchsia) ExtractFixTagsFromCommits(baseCommit, email string) ([]FixCommit, error) {
	return ctx.zircon.ExtractFixTagsFromCommits(baseCommit, email)
}

func (ctx *fuchsia) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (ctx *fuchsia) PreviousReleaseTags(commit string) ([]string, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}
