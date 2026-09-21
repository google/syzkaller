// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/gitlog"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestCheckout(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	ctx.Workdir = t.TempDir()
	repo := vcs.MakeTestRepo(t, filepath.Join(ctx.Workdir, "repo", targets.Linux))
	repo.Git("checkout", "-b", "master")
	var hashes []string
	for i := range 5 {
		hashes = append(hashes, repo.CommitChange(fmt.Sprintf("commit %v", i)).Hash)
	}
	// Check out a commit that is not the branch tip.
	const wantCommits = 3
	commit := hashes[wantCommits-1]

	res, err := checkout(ctx, checkoutArgs{KernelRepo: repo.Dir, KernelCommit: commit})
	require.NoError(t, err)
	require.Equal(t, commit, headCommit(t, res.KernelSrc))
	// The git tools work on KernelSrc, so it must contain the full commit history.
	require.Equal(t, wantCommits, gitLogCommits(t, res.KernelSrc))

	// The scratch checkout is used only for code edits, it does not need the history.
	scratch, err := checkoutScratch(ctx, checkoutScratchArgs(res))
	require.NoError(t, err)
	require.Equal(t, commit, headCommit(t, scratch.KernelScratchSrc))
	require.Equal(t, 1, gitLogCommits(t, scratch.KernelScratchSrc))
}

func headCommit(t *testing.T, kernelSrc string) string {
	output, err := vcs.Git{Dir: kernelSrc}.Run("rev-parse", "HEAD")
	require.NoError(t, err)
	return strings.TrimSpace(string(output))
}

// gitLogCommits returns the number of commits the git-log tool sees in the checkout.
func gitLogCommits(t *testing.T, kernelSrc string) int {
	// The tool requires at least one search mode, and the commits don't touch any files.
	res, err := aflow.TestToolRun(gitlog.ToolLog,
		map[string]any{"KernelSrc": kernelSrc},
		map[string]any{"MessageRegexps": []any{"commit"}})
	require.NoError(t, err)
	return strings.Count(res["Output"].(string), "\n")
}
