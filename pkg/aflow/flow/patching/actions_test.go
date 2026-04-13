// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestRecentCommits(t *testing.T) {
	// To avoid creating a fake git repo, we use the syzkaller repo itself.
	// On CI we have a shallow git checkout that does not have the commit.
	if os.Getenv("CI") != "" {
		t.Skip("skipping on CI because of shallow git checkout")
	}
	dir := t.TempDir()
	require.NoError(t, osutil.MkdirAll(filepath.Join(dir, "repo")))
	require.NoError(t, os.Symlink(osutil.Abs(filepath.FromSlash("../../../..")),
		filepath.Join(dir, "repo", "linux")))
	aflow.TestAction(t, getRecentCommits, dir, recentCommitsArgs{
		KernelCommit: "e01a0ca6c12c9851ea7090f13879255ef82291e7",
		PatchDiff: `
diff --git a/dashboard/app/ai.go b/dashboard/app/ai.go
index d4539113c..1d7401e61 100644
--- a/dashboard/app/ai.go
+++ b/dashboard/app/ai.go
@@ -1,2 +1,2 @@
-// Copyright 2025 syzkaller project authors. All rights reserved.
+// Copyright 2026 syzkaller project authors. All rights reserved.
 // Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
diff --git a/syz-cluster/pkg/fuzzconfig/generate.go b/syz-cluster/pkg/fuzzconfig/generate.go
index fa7d082e6..74ec57b49 100644
--- a/syz-cluster/pkg/fuzzconfig/generate.go
+++ b/syz-cluster/pkg/fuzzconfig/generate.go
@@ -1,2 +1,2 @@
-// Copyright 2025 syzkaller project authors. All rights reserved.
+// Copyright 2026 syzkaller project authors. All rights reserved.
 // Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
`,
	}, recentCommitsResult{RecentCommits: `dashboard: run patching ai jobs on custom base commits
dashboard/app: upload AI-generated patches to gerrit
dashboard: journal user actions on the ai dashboard
pkg/aflow/trajectory: add token usage
dashboard/app: add AI job running status
dashboard: filter AI jobs by workflows
syz-cluster: disable some trace calls for non-bpf targets
pkg/aflow: make LLM model per-agent rather than per-flow
dashboard/app: show crash report on AI job page
dashboard/app: improve AI UI
pkg/aflow: allow to specify model per-flow
dashboard/app: add race harmfullness label
dashboard/app: add manual AI job triage
pkg/aflow/flow/assessment: add UAF moderation workflow
dashboard/app: add support for AI workflows
syz-cluster: rewrite fuzz config generation
`,
	}, "")
}

func TestSyzlangToC(t *testing.T) {
	sysTarget := targets.Get("linux", "amd64")
	if runtime.GOOS != sysTarget.BuildOS || sysTarget.BrokenCompiler != "" {
		t.Skip("cannot build linux/amd64 on this host")
	}
	validProg := `r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
write(r0, &AUTO="01010101", 0x4)
`
	res, err := syzlangToCFunc(nil, syzlangToCArgs{ReproSyz: validProg})
	require.NoError(t, err)
	require.NotEmpty(t, res.SimplifiedCRepro)
	require.Contains(t, res.SimplifiedCRepro, "int main")
}

func TestSyzlangToC_Invalid(t *testing.T) {
	invalidProg := `r0 = unknown_syscall(0x123)`
	res, err := syzlangToCFunc(nil, syzlangToCArgs{ReproSyz: invalidProg})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse syz repro")
	require.Empty(t, res.SimplifiedCRepro)
}

func TestSyzlangToC_Empty(t *testing.T) {
	res, err := syzlangToCFunc(nil, syzlangToCArgs{ReproSyz: ""})
	require.Error(t, err)
	require.Contains(t, err.Error(), "syz repro is missing")
	require.Empty(t, res.SimplifiedCRepro)
}
