// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sandboxPipelineInputs struct {
	BaseRepository string
	BaseBranch     string
	BaseCommit     string
	TargetOS       string
	TargetArch     string
	TargetVMArch   string
	KernelConfig   string
	PatchHistory   []ai.PatchHistoryEntry
	PatchDiff      string
	Fixes          ai.FixesTag
}

type sandboxPipelineOutputs struct {
	KernelBranch     string
	KernelSrc        string
	KernelObj        string
	KernelScratchSrc string
	Recipients       []ai.Recipient
	RecentCommits    string
}

const sandboxPipelineType = ai.WorkflowType("test-sandbox-pipeline")

func init() {
	aflow.Register[sandboxPipelineInputs, sandboxPipelineOutputs](sandboxPipelineType, "test", &aflow.Flow{
		Root: aflow.Pipeline(
			baseCommitPicker,
			kernel.Checkout,
			kernel.Build,
			kernel.CheckoutScratch,
			applyGitPatch,
			getMaintainers,
			getRecentCommits,
		),
	})
}

// TestSandboxPipeline runs the main non-LLM parts of the patching workflow under the sandbox:
// it initializes the main kernel repo, creates the cached checkout and build, applies a patch
// to the scratch checkout, and runs the kernel scripts. Then it runs the same pipeline again
// on the same workdir with a re-created cache (as it happens after a restart).
func TestSandboxPipeline(t *testing.T) {
	osutil.RequireSandbox(t)
	dir := osutil.SandboxTempDir(t)
	remote, commit := build.MakeTestKernelRepo(t, filepath.Join(dir, "remote"))
	workdir := filepath.Join(dir, "workdir")
	require.NoError(t, osutil.MkdirAll(workdir))
	inputs := map[string]any{
		"BaseRepository": remote.Dir,
		"BaseBranch":     "master",
		"BaseCommit":     "HEAD",
		"TargetOS":       targets.Linux,
		"TargetArch":     targets.AMD64,
		"TargetVMArch":   targets.AMD64,
		"KernelConfig":   "CONFIG_FOO=y\n",
		"PatchHistory":   []ai.PatchHistoryEntry{{Version: 1, Diff: build.TestKernelPatch}},
		"PatchDiff":      build.TestKernelPatch,
		"Fixes":          ai.FixesTag{},
	}
	run := func() sandboxPipelineOutputs {
		cache, err := aflow.NewCache(filepath.Join(workdir, "cache"), 1<<30)
		require.NoError(t, err)
		res, err := aflow.Flows[string(sandboxPipelineType)].Execute(context.Background(), inputs,
			aflow.ExecuteOptions{
				Provider: &dummyProvider{},
				Workdir:  workdir,
				Cache:    cache,
				OnEvent:  func(*trajectory.Span) error { return nil },
				Logf:     func(_ int, msg string, args ...any) { t.Logf(msg, args...) },
			})
		require.NoError(t, err)
		var out sandboxPipelineOutputs
		for name, ptr := range map[string]*string{
			"KernelBranch":     &out.KernelBranch,
			"KernelSrc":        &out.KernelSrc,
			"KernelObj":        &out.KernelObj,
			"KernelScratchSrc": &out.KernelScratchSrc,
			"RecentCommits":    &out.RecentCommits,
		} {
			*ptr = res[name].(string)
		}
		out.Recipients = res["Recipients"].([]ai.Recipient)
		return out
	}

	first := run()
	assert.Equal(t, []ai.Recipient{{Name: "Foo Maintainer", Email: "foo@kernel.org", To: true}},
		first.Recipients)
	assert.Equal(t, "initial kernel commit\n", first.RecentCommits)
	assert.Equal(t, commit, headCommit(t, first.KernelSrc))
	// The scratch checkout is a temp dir, it's removed when the workflow finishes.
	assert.NoDirExists(t, first.KernelScratchSrc)

	second := run()
	assert.Equal(t, first.KernelSrc, second.KernelSrc)
	assert.Equal(t, first.KernelObj, second.KernelObj)
	assert.NotEqual(t, first.KernelScratchSrc, second.KernelScratchSrc)
	assert.Equal(t, first.Recipients, second.Recipients)
	assert.Equal(t, first.RecentCommits, second.RecentCommits)
}

func headCommit(t *testing.T, dir string) string {
	output, err := vcs.SandboxedGit(dir).Run("rev-parse", "HEAD")
	require.NoError(t, err)
	return strings.TrimSpace(string(output))
}
