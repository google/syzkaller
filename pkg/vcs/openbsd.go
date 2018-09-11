// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"io"
)

type openbsd struct {
	git *git
}

func newOpenBSD(vm, dir string) *openbsd {
	return &openbsd{
		git: newGit(dir),
	}
}

func (ctx *openbsd) Poll(repo, branch string) (*Commit, error) {
	return ctx.git.Poll(repo, branch)
}

func (ctx *openbsd) CheckoutBranch(repo, branch string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for openbsd")
}

func (ctx *openbsd) CheckoutCommit(repo, commit string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for openbsd")
}

func (ctx *openbsd) SwitchCommit(commit string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for openbsd")
}

func (ctx *openbsd) HeadCommit() (*Commit, error) {
	return nil, fmt.Errorf("not implemented for openbsd")
}

func (ctx *openbsd) ListRecentCommits(baseCommit string) ([]string, error) {
	return ctx.git.ListRecentCommits(baseCommit)
}

func (ctx *openbsd) ExtractFixTagsFromCommits(baseCommit, email string) ([]FixCommit, error) {
	return ctx.git.ExtractFixTagsFromCommits(baseCommit, email)
}

func (ctx *openbsd) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for openbsd")
}

func (ctx *openbsd) PreviousReleaseTags(commit string) ([]string, error) {
	return nil, fmt.Errorf("not implemented for openbsd")
}
