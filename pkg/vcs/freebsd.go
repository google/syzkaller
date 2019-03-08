// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"io"
)

type freebsd struct {
	*git
}

func newFreeBSD(vm, dir string) *freebsd {
	return &freebsd{
		git: newGit(dir),
	}
}

func (ctx *freebsd) ExtractFixTagsFromCommits(baseCommit, email string) ([]*Commit, error) {
	return ctx.git.ExtractFixTagsFromCommits(baseCommit, email)
}

func (ctx *freebsd) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for freebsd")
}

func (ctx *freebsd) PreviousReleaseTags(commit string) ([]string, error) {
	return nil, fmt.Errorf("not implemented for freebsd")
}
