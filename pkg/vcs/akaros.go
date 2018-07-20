// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"io"
	"path/filepath"
)

type akaros struct {
	git      *git
	dropbear *git
}

func newAkaros(vm, dir string) *akaros {
	return &akaros{
		git:      newGit("", vm, dir),
		dropbear: newGit("", vm, filepath.Join(dir, "dropbear")),
	}
}

func (ctx *akaros) Poll(repo, branch string) (*Commit, error) {
	if _, err := ctx.dropbear.Poll("https://github.com/akaros/dropbear-akaros", "akaros"); err != nil {
		return nil, err
	}
	return ctx.git.Poll(repo, branch)
}

func (ctx *akaros) CheckoutBranch(repo, branch string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for akaros")
}

func (ctx *akaros) CheckoutCommit(repo, commit string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for akaros")
}

func (ctx *akaros) SwitchCommit(commit string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for akaros")
}

func (ctx *akaros) HeadCommit() (*Commit, error) {
	return nil, fmt.Errorf("not implemented for akaros")
}

func (ctx *akaros) ListRecentCommits(baseCommit string) ([]string, error) {
	return ctx.git.ListRecentCommits(baseCommit)
}

func (ctx *akaros) ExtractFixTagsFromCommits(baseCommit, email string) ([]FixCommit, error) {
	return ctx.git.ExtractFixTagsFromCommits(baseCommit, email)
}

func (ctx *akaros) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for akaros")
}

func (ctx *akaros) PreviousReleaseTags(commit string) ([]string, error) {
	return nil, fmt.Errorf("not implemented for akaros")
}
