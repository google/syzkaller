// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/gitlog"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckout(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	ctx.Workdir = osutil.SandboxTempDir(t)
	repo := vcs.MakeTestRepo(t, osutil.SandboxTempDir(t))
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

func TestKernelSandbox(t *testing.T) {
	osutil.RequireSandbox(t)
	dir := osutil.SandboxTempDir(t)
	secret := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(secret, []byte("secret"), 0600))
	t.Setenv("SYZ_TEST_FORBIDDEN", secret)

	remote, commit := build.MakeTestKernelRepo(t, filepath.Join(dir, "remote"))
	ctx := aflow.NewTestContext(t)
	ctx.Workdir = osutil.SandboxTempDir(t)

	src, err := checkout(ctx, checkoutArgs{KernelRepo: remote.Dir, KernelCommit: commit})
	require.NoError(t, err)

	_, err = buildKernel(ctx, buildArgs{
		TargetOS:     targets.Linux,
		TargetArch:   targets.AMD64,
		KernelSrc:    src.KernelSrc,
		KernelCommit: commit,
		KernelConfig: "CONFIG_FOO=y\n",
	})
	require.NoError(t, err)

	scratch, err := checkoutScratch(ctx, checkoutScratchArgs(src))
	require.NoError(t, err)
	_, hasIssues, err := Checkpatch(scratch.KernelScratchSrc)
	require.NoError(t, err)
	require.False(t, hasIssues)

	t.Run("disabled", func(t *testing.T) {
		t.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
		err := BuildKernel(osutil.SandboxTempDir(t), src.KernelSrc,
			"CONFIG_FOO=y\n", targets.Linux, targets.AMD64, "", true)
		require.Error(t, err)
		for _, msg := range []string{
			"user is root, want syzkaller",
			"able to read " + secret,
			"able to write " + secret,
			"able to write to " + dir,
			"able to connect to local TCP port",
		} {
			assert.Contains(t, osutil.VerboseMessage(err), msg)
		}
	})
}

func headCommit(t *testing.T, kernelSrc string) string {
	output, err := vcs.SandboxedGit(kernelSrc).Run("rev-parse", "HEAD")
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
