// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

type testos struct {
	*git
}

func newTestos(dir string) *testos {
	return &testos{
		git: newGit(dir, nil),
	}
}

func (ctx *testos) PreviousReleaseTags(commit string) ([]string, error) {
	return ctx.git.previousReleaseTags(commit, false)
}

func (ctx *testos) EnvForCommit(binDir, commit string, kernelConfig []byte) (*BisectEnv, error) {
	return &BisectEnv{}, nil
}
