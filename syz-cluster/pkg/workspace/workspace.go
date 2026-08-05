// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package workspace manages repository checkouts and patch application for workflow actions.
package workspace

import (
	"fmt"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/triage"
)

type Workspace struct {
	*triage.GitTreeOps
	dir    string
	tracer debugtracer.DebugTracer
}

// New initializes a Workspace for the specified repository directory.
func New(dir string, tracer debugtracer.DebugTracer) (*Workspace, error) {
	ops, err := triage.NewGitTreeOps(dir, true)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize repository: %w", err)
	}
	return &Workspace{
		GitTreeOps: ops,
		dir:        dir,
		tracer:     tracer,
	}, nil
}

// Checkout checks out the given commit (or branch within treeName) and applies the provided patch series.
func (ws *Workspace) Checkout(treeName, commit string, patches [][]byte) (*vcs.Commit, error) {
	if ws.tracer != nil {
		ws.tracer.Logf("checking out %q in %q", commit, treeName)
	}
	vcsCommit, err := ws.GitTreeOps.Commit(treeName, commit)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit info: %w", err)
	}
	if len(patches) > 0 && ws.tracer != nil {
		ws.tracer.Logf("applying %d patches", len(patches))
	}
	if err := ws.ApplySeries(vcsCommit.Hash, patches); err != nil {
		return nil, fmt.Errorf("failed to apply series: %w", err)
	}
	return vcsCommit, nil
}

// CommitPatches stages and commits applied patches into git history for AI evaluation tools.
func (ws *Workspace) CommitPatches() error {
	return triage.CommitPatchForAflow(ws.GitTreeOps)
}
