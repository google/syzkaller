// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"path/filepath"
)

type akaros struct {
	*git
	dropbear *git
}

func newAkaros(vm, dir string) *akaros {
	return &akaros{
		git:      newGit(dir, nil),
		dropbear: newGit(filepath.Join(dir, "dropbear"), nil),
	}
}

func (ctx *akaros) Poll(repo, branch string) (*Commit, error) {
	if _, err := ctx.dropbear.Poll("https://github.com/akaros/dropbear-akaros", "akaros"); err != nil {
		return nil, err
	}
	return ctx.git.Poll(repo, branch)
}
