// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/require"
)

func TestWorkflowFindingTriageRegistered(t *testing.T) {
	flow := aflow.Flows[string(ai.WorkflowFindingTriage)]
	require.NotNil(t, flow, "WorkflowFindingTriage must be registered in aflow.Flows")
}

func TestPrepareFindingOverview(t *testing.T) {
	tmpDir := t.TempDir()
	repoDir := filepath.Join(tmpDir, "repo", "linux")
	repo := vcs.MakeTestRepo(t, repoDir)

	repo.CommitChangeset("initial commit", vcs.FileContent{
		File:    "foo.c",
		Content: "void foo() {}\n",
	})
	repo.CommitChangeset("second commit", vcs.FileContent{
		File:    "foo.c",
		Content: "void foo() { int x = 1; }\n",
	})

	patches := []ai.SeriesPatch{
		{Seq: 1, Title: "net: fix foo"},
		{Seq: 2, Title: "net: fix bar"},
	}

	aflow.TestAction(t, prepareFindingOverview, tmpDir,
		prepareFindingOverviewArgs{
			KernelSrc: repoDir,
			Patches:   patches,
		},
		prepareFindingOverviewResult{
			DiffStat:   "foo.c | 2 +-\n 1 file changed, 1 insertion(+), 1 deletion(-)",
			PatchList:  "[1] net: fix foo\n[2] net: fix bar",
			PatchCount: 2,
		},
		"")

	// Test with cover letter.
	patchesWithCover := []ai.SeriesPatch{
		{Seq: 0, Title: "net: fix bugs"},
		{Seq: 1, Title: "net: fix foo"},
	}
	aflow.TestAction(t, prepareFindingOverview, tmpDir,
		prepareFindingOverviewArgs{
			KernelSrc: repoDir,
			Patches:   patchesWithCover,
		},
		prepareFindingOverviewResult{
			DiffStat:   "foo.c | 2 +-\n 1 file changed, 1 insertion(+), 1 deletion(-)",
			PatchList:  "[0] (Cover letter) net: fix bugs\n[1] net: fix foo",
			PatchCount: 2,
		},
		"")

	// Test with empty KernelSrc.
	aflow.TestAction(t, prepareFindingOverview, tmpDir,
		prepareFindingOverviewArgs{
			KernelSrc: "",
			Patches:   patches,
		},
		prepareFindingOverviewResult{
			DiffStat:   "",
			PatchList:  "[1] net: fix foo\n[2] net: fix bar",
			PatchCount: 2,
		},
		"")
}
