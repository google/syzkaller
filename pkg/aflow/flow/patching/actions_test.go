// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecentCommits(t *testing.T) {
	// To avoid creating a fake git repo, we use the syzkaller repo itself.
	// On CI we have a shallow git checkout that does not have the commit.
	if os.Getenv("CI") != "" {
		t.Skip("skipping on CI because of shallow git checkout")
	}
	aflow.TestAction(t, getRecentCommits, "", recentCommitsArgs{
		KernelSrc:    osutil.Abs(filepath.FromSlash("../../../..")),
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
diff --git a/dashboard/app/brand_new_file.go b/dashboard/app/brand_new_file.go
new file mode 100644
index 000000000..1d7401e61
--- /dev/null
+++ b/dashboard/app/brand_new_file.go
@@ -0,0 +1 @@
+// Copyright 2026 syzkaller project authors. All rights reserved.
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

func TestMaintainers(t *testing.T) {
	osutil.RequireSandbox(t)
	dir := osutil.SandboxTempDir(t)
	secret := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(secret, []byte("secret"), 0600))
	t.Setenv("SYZ_TEST_FORBIDDEN", secret)

	repo, _ := build.MakeTestKernelRepo(t, filepath.Join(dir, "repo"))
	args := maintainersArgs{
		KernelSrc: repo.Dir,
		PatchDiff: "fake patch diff",
		Fixes: ai.FixesTag{
			Hash:        "123456789",
			Title:       "some fix",
			AuthorName:  "Fixes Author",
			AuthorEmail: "fixes@example.com",
		},
	}
	aflow.TestAction(t, getMaintainers, "", args, maintainersResult{
		Recipients: []ai.Recipient{
			{Name: "Foo Maintainer", Email: "foo@kernel.org", To: true},
			{Name: "Fixes Author", Email: "fixes@example.com", To: true},
		},
	}, "")

	t.Run("disabled", func(t *testing.T) {
		t.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
		_, err := maintainers(aflow.NewTestContext(t), args)
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
