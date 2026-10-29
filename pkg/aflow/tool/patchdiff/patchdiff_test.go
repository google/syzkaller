// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patchdiff

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatchDiff(t *testing.T) {
	tmpDir := osutil.SandboxTempDir(t)
	repoDir := filepath.Join(tmpDir, "repo", "linux")
	repo := vcs.MakeTestRepo(t, repoDir)

	repo.CommitChangeset("initial commit", vcs.FileContent{
		File: "foo.c",
		Content: `
#include <stdio.h>

void helper() {
	printf("helper\n");
}

void foo() {
	// BUG HERE
	printf("foo\n");
}

void bar() {
	printf("bar\n");
}

int main() {
	foo();
	bar();
	return 0;
}
`,
	})

	// Make an uncommitted change in the middle of a longer file.
	osutil.WriteSandboxFile(t, filepath.Join(repoDir, "foo.c"), []byte(`
#include <stdio.h>

void helper() {
	printf("helper\n");
}

void foo() {
	// fixed!
	printf("foo\n");
}

void bar() {
	printf("bar\n");
}

int main() {
	foo();
	bar();
	return 0;
}
`))

	// Test a successful diff with expanded context.
	aflow.TestTool(t, Tool,
		state{KernelScratchSrc: repoDir},
		args{},
		func(res result) {
			// Strip the dynamic index line to do a clean string comparison.
			output := regexp.MustCompile(`(?m)^index [0-9a-f]+\.\.[0-9a-f]+ 100644\n`).ReplaceAllString(res.Output, "")
			expected := `diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -1,19 +1,19 @@
 
 #include <stdio.h>
 
 void helper() {
 	printf("helper\n");
 }
 
 void foo() {
-	// BUG HERE
+	// fixed!
 	printf("foo\n");
 }
 
 void bar() {
 	printf("bar\n");
 }
 
 int main() {
 	foo();
 	bar();
`
			assert.Equal(t, expected, output)
		},
		"", aflow.TestWorkdir(tmpDir))

	// Test a call without any arguments (the way an LLM calls it), File must be optional
	// and the result must be exactly the same as with an explicitly empty File.
	toolState := map[string]any{"KernelScratchSrc": repoDir}
	resNoArgs, err := aflow.TestToolRun(Tool, toolState, map[string]any{})
	require.NoError(t, err)
	resEmptyFile, err := aflow.TestToolRun(Tool, toolState, map[string]any{"File": ""})
	require.NoError(t, err)
	require.Equal(t, resEmptyFile, resNoArgs)

	// Test restricting diff to a specific file.
	aflow.TestTool(t, Tool,
		state{KernelScratchSrc: repoDir},
		args{File: "foo.c"},
		func(res result) {
			assert.Regexp(t, `-\s*// BUG HERE`, res.Output)
		},
		"", aflow.TestWorkdir(tmpDir))

	// Test a non-existent file, it should just return an empty diff without erroring.
	aflow.TestTool(t, Tool,
		state{KernelScratchSrc: repoDir},
		args{File: "nonexistent.c"},
		func(res result) {
			assert.Empty(t, res.Output)
		},
		"", aflow.TestWorkdir(tmpDir))

	// Test an out-of-bounds file, should return an aflow.BadCallError from git.
	aflow.TestTool(t, Tool,
		state{KernelScratchSrc: repoDir},
		args{File: "../outside.c"},
		result{},
		"git diff failed: the file is outside the repository",
		aflow.TestWorkdir(tmpDir))
}

func TestPatchDiffSandbox(t *testing.T) {
	osutil.RequireSandbox(t)
	repo := vcs.MakeTestRepo(t, osutil.SandboxTempDir(t))
	cfg := filepath.Join(repo.Dir, ".git", "config")
	require.NoError(t, os.Chown(cfg, 0, 0))
	require.NoError(t, os.Chmod(cfg, 0600))
	_, err := aflow.TestToolRun(Tool, map[string]any{"KernelScratchSrc": repo.Dir}, map[string]any{})
	require.ErrorAs(t, err, new(*osutil.VerboseError))
	assert.Contains(t, osutil.VerboseMessage(err), "Permission denied")
}
