// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

type GitTreeOps struct {
	dir string
	*vcs.GitWrapper
}

func NewGitTreeOps(dir string, sandbox bool) (*GitTreeOps, error) {
	ops := &GitTreeOps{
		GitWrapper: &vcs.GitWrapper{
			Dir:     dir,
			Sandbox: sandbox, // TODO: why doesn't sandbox=true work normally under go tests?
			Env:     os.Environ(),
		},
	}
	err := ops.Reset()
	return ops, err
}

func (ops *GitTreeOps) HeadCommit(tree *api.Tree) (*vcs.Commit, error) {
	// See kernel-disk/cron.yaml.
	return ops.Commit(tree.Name + "-head")
}

func (ops *GitTreeOps) ApplySeries(commit string, patches [][]byte) error {
	ops.Reset()
	_, err := ops.Git("reset", "--hard", commit)
	if err != nil {
		return err
	}
	for i, patch := range patches {
		err := ops.Apply(patch)
		if err != nil {
			return fmt.Errorf("failed to apply patch %d: %w", i, err)
		}
	}
	return nil
}
