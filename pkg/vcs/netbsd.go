// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"io"
)

type netbsd struct {
	*git
}

func newNetBSD(vm, dir string) *netbsd {
	return &netbsd{
		git: newGit(dir),
	}
}

func (ctx *netbsd) ExtractFixTagsFromCommits(baseCommit, email string) ([]*Commit, error) {
	return ctx.git.ExtractFixTagsFromCommits(baseCommit, email)
}

func (ctx *netbsd) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for netbsd")
}

func (ctx *netbsd) PreviousReleaseTags(commit string) ([]string, error) {
	return nil, fmt.Errorf("not implemented for netbsd")
}
